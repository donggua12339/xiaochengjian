import {
  Injectable,
  BadRequestException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * 梆梆加固自检 EULA 服务(ADR 0078 锁 B)
 *
 * 锁 B 约束:admin-web 上必须先勾选 EULA 才能启用梆梆自检,无 EULA 不开放
 *
 * EULA 文本维护在 docs/compliance/audit-eula.md,版本号变化需重新勾选。
 * 接受状态(developerId + eulaVersion + acceptedAt)记入 audit_log_own 表的
 * hardener/eulaVersion/eulaAccepted 字段(每次梆梆自检时记录)。
 *
 * 本 service 维护当前 EULA 版本号 + 验证开发者是否已接受。
 */

export const CURRENT_EULA_VERSION = '1.0.0';

export interface EulaInfo {
  version: string;
  text: string;
  effectiveDate: string;
}

/**
 * EULA 文本(摘要,完整版见 docs/compliance/audit-eula.md)
 *
 * 注:实际部署时从 docs/compliance/audit-eula.md 读取,这里硬编码摘要供 API 返回。
 * 版本号变化时需同步更新 CURRENT_EULA_VERSION + 此处文本。
 */
const EULA_SUMMARY = `自有 APK 诊断 EULA(梆梆加固自检场景)

版本:${CURRENT_EULA_VERSION}
生效日期:2026-07-20

本人声明:
1. 待诊断 APK 是本人自有(合法著作权或授权)
2. 不绕过梆梆保护(仅完整性扫描,不脱壳不反编译)
3. 不用于入侵他人系统
4. 不要求扩展到其他加固厂商(仅梆梆)

工具能力:梆梆 so 完整性报告 + API 扫描 + 签名验证(不输出源码)
禁止:脱壳 / 反编译 / 运行 APK / 处理非梆梆加固

审计日志记录所有操作(含 EULA 接受状态),保留 1 年。
违反 EULA 可终止服务 + 披露违规行为。

完整 EULA 见 docs/compliance/audit-eula.md`;

@Injectable()
export class HardenerEulaService {
  private readonly logger = new Logger(HardenerEulaService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * 获取当前 EULA 文本 + 版本号
   */
  getCurrentEula(): EulaInfo {
    return {
      version: CURRENT_EULA_VERSION,
      text: EULA_SUMMARY,
      effectiveDate: '2026-07-20',
    };
  }

  /**
   * 验证开发者是否已接受当前版本 EULA
   *
   * 查询 audit_log_own 表,看该开发者是否有 eulaAccepted=true 且 eulaVersion=CURRENT 的记录
   *
   * @throws ForbiddenException 未接受当前版本 EULA(EULA_REQUIRED)
   */
  async validateAccepted(developerId: string): Promise<void> {
    const accepted = await this.prisma.auditLogOwn.findFirst({
      where: {
        developerId,
        eulaAccepted: true,
        eulaVersion: CURRENT_EULA_VERSION,
        hardener: 'bangcle',
      },
      select: { id: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });

    if (!accepted) {
      throw new ForbiddenException('EULA_REQUIRED', {
        cause: `developer must accept EULA v${CURRENT_EULA_VERSION} before using bangcle hardener audit (ADR 0078 锁 B)`,
      });
    }
  }

  /**
   * 记录开发者接受 EULA
   *
   * 在 audit_log_own 表插入一条记录:
   *  - operation = 'EULA_ACCEPT'(非 ANALYZE / RESIGN)
   *  - hardener = 'bangcle'
   *  - eulaVersion = CURRENT
   *  - eulaAccepted = true
   *
   * 注:此记录不关联具体 APK,apkHash/packageName 等字段填占位值
   */
  async recordAcceptance(developerId: string, ip: string, userAgent?: string): Promise<void> {
    await this.prisma.auditLogOwn.create({
      data: {
        developerId,
        appId: 'eula-accept', // 占位,不关联具体应用
        apkHash: 'n/a',
        apkSize: 0,
        packageName: 'n/a',
        signatureHash: 'n/a',
        check1Passed: true,
        check2Passed: true,
        check3Passed: true,
        status: 'SUCCESS',
        operation: 'EULA_ACCEPT',
        hardener: 'bangcle',
        eulaVersion: CURRENT_EULA_VERSION,
        eulaAccepted: true,
        ip,
        userAgent: userAgent ?? null,
      },
    });

    this.logger.log(
      `EULA v${CURRENT_EULA_VERSION} 已接受: developerId=${developerId}`,
    );
  }

  /**
   * 验证 EULA 版本号是否合法(防止客户端伪造)
   */
  validateVersion(version: string): void {
    if (version !== CURRENT_EULA_VERSION) {
      throw new BadRequestException('EULA_VERSION_MISMATCH', {
        cause: `expected v${CURRENT_EULA_VERSION}, got v${version}`,
      });
    }
  }
}
