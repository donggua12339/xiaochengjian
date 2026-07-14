import {
  Injectable,
  BadRequestException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { RedisService } from '../redis/redis.service';

const execFileAsync = promisify(execFile);

/**
 * APK 注入服务
 * 详见 ADR 0028(注入工具架构)/ E1(安卓端注入)/ 0030(防滥用)
 *
 * 流程:
 *  1. 接收 APK + keystore + 密码
 *  2. 调用 xcj-injector-all.jar 处理(dex 注入 + 水印 + 签名)
 *  3. 注入后的 APK 存临时目录(5 分钟 TTL,过期自动删)
 *  4. 返回下载令牌,开发者用令牌下载
 *
 * 合规(ADR E1):
 *  - 原始 APK 处理完立即删除(不持久化)
 *  - 注入后 APK 5 分钟后自动删除
 *  - keystore 处理完立即删除
 */
@Injectable()
export class InjectService {
  private readonly logger = new Logger(InjectService.name);
  private readonly workDir: string;
  private readonly jarPath: string;
  private readonly resultTtl = 5 * 60; // 5 分钟

  constructor(
    private readonly redis: RedisService,
  ) {
    // 工作目录:/tmp/xcj-inject/
    this.workDir = process.env.XCJ_INJECT_WORK_DIR || '/tmp/xcj-inject';
    if (!fs.existsSync(this.workDir)) {
      fs.mkdirSync(this.workDir, { recursive: true });
    }
    // jar 路径(注入工具 fat jar)
    this.jarPath = process.env.XCJ_INJECTOR_JAR || '/opt/xcj-injector/xcj-injector-all.jar';
  }

  /**
   * 执行注入
   * @returns 下载令牌
   */
  async inject(
    apkFile: Express.Multer.File,
    keystoreFile: Express.Multer.File,
    params: { ksPass: string; ksKeyAlias: string; keyPass: string; watermarkId: string },
  ): Promise<{ downloadToken: string; originalSize: number; injectedSize: number; watermarkId: string }> {
    // 验证 jar 存在
    if (!fs.existsSync(this.jarPath)) {
      throw new BadRequestException('INJECTOR_JAR_NOT_FOUND');
    }

    // 验证 Java 可用
    try {
      await execFileAsync('java', ['-version']);
    } catch {
      throw new BadRequestException('JAVA_NOT_AVAILABLE');
    }

    // 验证文件
    if (!apkFile || !apkFile.buffer) {
      throw new BadRequestException('APK_FILE_REQUIRED');
    }
    if (!keystoreFile || !keystoreFile.buffer) {
      throw new BadRequestException('KEYSTORE_FILE_REQUIRED');
    }

    // 生成任务 ID + 临时目录
    const taskId = crypto.randomBytes(8).toString('hex');
    const taskDir = path.join(this.workDir, taskId);
    fs.mkdirSync(taskDir, { recursive: true });

    const inputApk = path.join(taskDir, 'input.apk');
    const outputApk = path.join(taskDir, 'output.apk');
    const keystorePath = path.join(taskDir, 'release.keystore');

    try {
      // 写入文件
      fs.writeFileSync(inputApk, apkFile.buffer);
      fs.writeFileSync(keystorePath, keystoreFile.buffer);
      const originalSize = apkFile.buffer.length;

      this.logger.log(`注入任务 ${taskId}: 原始 APK ${originalSize} 字节`);

      // 调用注入工具 jar
      const args = [
        '-jar', this.jarPath,
        '--input', inputApk,
        '--output', outputApk,
        '--keystore', keystorePath,
        '--ks-pass', params.ksPass,
        '--ks-key-alias', params.ksKeyAlias,
        '--key-pass', params.keyPass,
        '--watermark-id', params.watermarkId,
      ];

      const { stdout, stderr } = await execFileAsync('java', args, {
        timeout: 120000, // 2 分钟超时
        maxBuffer: 10 * 1024 * 1024,
      });

      if (stdout) this.logger.log(`注入工具输出: ${stdout.substring(0, 500)}`);
      if (stderr) this.logger.warn(`注入工具 stderr: ${stderr.substring(0, 500)}`);

      // 验证输出
      if (!fs.existsSync(outputApk)) {
        throw new BadRequestException('INJECT_FAILED_NO_OUTPUT');
      }
      const injectedSize = fs.statSync(outputApk).size;

      // 生成下载令牌
      const downloadToken = crypto.randomBytes(16).toString('hex');
      const resultKey = `inject_result:${downloadToken}`;
      // 存令牌 -> 任务目录映射,5 分钟 TTL
      await this.redis.set(resultKey, taskDir, this.resultTtl);

      // 设置 5 分钟后自动清理任务目录
      setTimeout(() => {
        this.cleanupTask(taskDir);
      }, this.resultTtl * 1000);

      this.logger.log(`注入任务 ${taskId} 完成: 输出 ${injectedSize} 字节, 令牌 ${downloadToken.substring(0, 8)}...`);

      return {
        downloadToken,
        originalSize,
        injectedSize,
        watermarkId: params.watermarkId,
      };
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      this.logger.error(`注入任务 ${taskId} 失败: ${errMsg}`);
      this.cleanupTask(taskDir);
      throw new BadRequestException(`INJECT_FAILED: ${errMsg}`);
    } finally {
      // 立即删除原始 APK + keystore(合规:不持久化)
      try {
        if (fs.existsSync(inputApk)) fs.unlinkSync(inputApk);
        if (fs.existsSync(keystorePath)) fs.unlinkSync(keystorePath);
      } catch {}
    }
  }

  /**
   * 下载注入后的 APK
   * @returns 文件路径(供 controller 流式返回)
   */
  async download(downloadToken: string): Promise<{ filePath: string; fileName: string }> {
    const resultKey = `inject_result:${downloadToken}`;
    const taskDir = await this.redis.get(resultKey);

    if (!taskDir) {
      throw new NotFoundException('DOWNLOAD_TOKEN_EXPIRED_OR_INVALID');
    }

    const outputApk = path.join(taskDir, 'output.apk');
    if (!fs.existsSync(outputApk)) {
      throw new NotFoundException('OUTPUT_FILE_NOT_FOUND');
    }

    return {
      filePath: outputApk,
      fileName: `xcj-injected-${Date.now()}.apk`,
    };
  }

  /**
   * 清理任务目录
   */
  private cleanupTask(taskDir: string) {
    try {
      if (fs.existsSync(taskDir)) {
        fs.rmSync(taskDir, { recursive: true, force: true });
        this.logger.log(`已清理任务目录: ${taskDir}`);
      }
    } catch (e) {
      this.logger.error(`清理任务目录失败: ${taskDir}, ${(e as Error).message}`);
    }
  }
}
