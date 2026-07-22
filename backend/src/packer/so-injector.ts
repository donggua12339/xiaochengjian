import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * 30 池随机 .so 名(看起来像普通第三方库,防特征扫描)
 *
 * 详见 ADR 0088 §.so 注入 + 30 池随机名
 *
 * 每次 Packer 封装时从池中随机选 1 个,作为 libxcj_defender.so 的伪装名。
 * 30 个名字覆盖常见第三方库命名风格(helper/util/engine/bridge 等),
 * 避免特征扫描通过固定 .so 名定位 defender。
 */
const SO_NAME_POOL: readonly string[] = [
  'libsec_helper.so',
  'libutil_codec.so',
  'libsys_util.so',
  'libcore_helper.so',
  'libnet_helper.so',
  'libdata_util.so',
  'libapp_helper.so',
  'libdev_utils.so',
  'libio_helper.so',
  'libbase_util.so',
  'libnative_helper.so',
  'libplatform.so',
  'libengine.so',
  'libframework.so',
  'libruntime.so',
  'libcommon.so',
  'libsupport.so',
  'libbridge.so',
  'libchannel.so',
  'libdispatch.so',
  'libprocessor.so',
  'libhandler.so',
  'libmanager.so',
  'libservice.so',
  'libprovider.so',
  'libres.so',
  'libmedia.so',
  'librender.so',
  'libscene.so',
  'liblayout.so',
] as const;

/** 支持的 ABI(与 defender-sdk CMakeLists.txt 双 ABI 对齐) */
const SUPPORTED_ABIS = ['arm64-v8a', 'armeabi-v7a'] as const;

/** .aar 内部的 .so 原始名(与 CMakeLists.txt add_library 对齐) */
const AAR_ORIGINAL_SO_NAME = 'libxcj_defender.so';

/**
 * .so 注入器(ADR 0088 §Packer 集成)
 *
 * 功能:
 *  1. 从 defender-sdk .aar 提取 jni/<abi>/libxcj_defender.so
 *  2. 从 30 池随机选 1 个伪装名
 *  3. 重命名后注入到 APK 的 lib/<abi>/<randomName>.so
 *  4. 返回随机名(供 Manifest meta-data "xcj.defender.lib" 使用)
 *
 * 安全约束:
 *  - .so 来自固定 .aar(SHA-256 白名单校验,锁 2 内容锁定)
 *  - 不修改 .so 内容(只重命名)
 *  - 注入到 lib/ 目录(系统只读,防运行时篡改)
 */
@Injectable()
export class SoInjector {
  private readonly logger = new Logger(SoInjector.name);

  /**
   * 从 30 池随机选一个 .so 名
   */
  pickRandomSoName(): string {
    const idx = crypto.randomInt(0, SO_NAME_POOL.length);
    return SO_NAME_POOL[idx];
  }

  /**
   * 从 defender-sdk .aar 提取 .so 文件
   *
   * .aar 内部结构:
   *   jni/arm64-v8a/libxcj_defender.so
   *   jni/armeabi-v7a/libxcj_defender.so
   *
   * @param aarPath .aar 文件路径
   * @param workDir 工作目录(提取的 .so 存放处)
   * @returns 每个 ABI 的 .so 路径
   */
  async extractSoFromAar(
    aarPath: string,
    workDir: string,
  ): Promise<{
    abis: { abi: string; soPath: string }[];
  }> {
    const extractDir = path.join(workDir, 'aar-extracted');
    await fs.mkdir(extractDir, { recursive: true });

    try {
      await execFileAsync('unzip', ['-o', aarPath, `jni/*`, '-d', extractDir], { timeout: 30_000 });
    } catch (e) {
      throw new BadRequestException('AAR_EXTRACT_FAILED', {
        cause: `failed to extract .so from aar: ${(e as Error).message}`,
      });
    }

    const abis: { abi: string; soPath: string }[] = [];
    for (const abi of SUPPORTED_ABIS) {
      const srcSo = path.join(extractDir, 'jni', abi, AAR_ORIGINAL_SO_NAME);
      try {
        await fs.access(srcSo);
        abis.push({ abi, soPath: srcSo });
      } catch {
        this.logger.warn(`AAR 缺少 ${abi} 的 .so,跳过该 ABI`);
      }
    }

    if (abis.length === 0) {
      throw new BadRequestException('NO_SO_IN_AAR', {
        cause: `no .so found in defender-sdk aar (expected jni/*/libxcj_defender.so)`,
      });
    }

    this.logger.log(`从 AAR 提取 ${abis.length} 个 ABI 的 .so`);
    return { abis };
  }

  /**
   * 注入 .so 到 APK(随机伪装名)
   *
   * @param apkPath APK 路径
   * @param abisFromAar 从 AAR 提取的 .so 列表
   * @param workDir 工作目录
   * @returns 随机选的 .so 名(供 Manifest meta-data 用)+ 注入 .so 的 SHA-256
   */
  async injectSo(
    apkPath: string,
    abisFromAar: { abi: string; soPath: string }[],
    workDir: string,
  ): Promise<{
    randomSoName: string;
    injectedSoHash: string;
  }> {
    const randomSoName = this.pickRandomSoName();

    // 准备 staging 目录:lib/<abi>/<randomSoName>
    const stagingDir = path.join(workDir, 'so-staging');
    await fs.rm(stagingDir, { recursive: true, force: true });
    await fs.mkdir(stagingDir, { recursive: true });

    const relPaths: string[] = [];
    for (const { abi, soPath } of abisFromAar) {
      const abiDir = path.join(stagingDir, 'lib', abi);
      await fs.mkdir(abiDir, { recursive: true });
      const destSo = path.join(abiDir, randomSoName);
      await fs.copyFile(soPath, destSo);
      relPaths.push(`lib/${abi}/${randomSoName}`);
    }

    // 计算注入 .so 的 hash(arm64-v8a 优先,作为所有 ABI 的代表 hash)
    const primaryAbi = abisFromAar.find((a) => a.abi === 'arm64-v8a') ?? abisFromAar[0];
    const hashSoPath = path.join(stagingDir, 'lib', primaryAbi.abi, randomSoName);
    const soContent = await fs.readFile(hashSoPath);
    const injectedSoHash = crypto.createHash('sha256').update(soContent).digest('hex');

    // 注入到 APK(保持 lib/<abi>/ 目录结构)
    // zip 命令:cd stagingDir && zip apkPath lib/arm64-v8a/... lib/armeabi-v7a/...
    try {
      await execFileAsync('zip', [apkPath, ...relPaths], { timeout: 30_000, cwd: stagingDir });
      this.logger.log(
        `.so 注入完成:${randomSoName} (${abisFromAar.length} ABI, SHA-256: ${injectedSoHash.slice(0, 16)}...)`,
      );
    } catch (e) {
      throw new BadRequestException('SO_INJECT_FAILED', {
        cause: `failed to inject .so into apk: ${(e as Error).message}`,
      });
    }

    return { randomSoName, injectedSoHash };
  }

  /**
   * 校验 .aar 的 SHA-256 是否在白名单内(锁 2 内容锁定)
   *
   * @param aarPath .aar 路径
   * @param whitelist 允许的 .aar SHA-256 列表
   * @throws BadRequestException .aar 不在白名单
   */
  async validateAarHash(aarPath: string, whitelist: string[]): Promise<{ aarHash: string }> {
    const aarContent = await fs.readFile(aarPath);
    const aarHash = crypto.createHash('sha256').update(aarContent).digest('hex');

    if (whitelist.length === 0) {
      this.logger.warn('defender-sdk .aar 白名单为空,跳过校验(MVP)');
      return { aarHash };
    }

    const matched = whitelist.some((h) => h.toLowerCase() === aarHash.toLowerCase());
    if (!matched) {
      throw new BadRequestException('DEFENDER_AAR_NOT_WHITELISTED', {
        cause: `defender-sdk aar hash ${aarHash.slice(0, 16)}... not in whitelist (锁 2)`,
      });
    }

    return { aarHash };
  }
}
