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

export type SupportedHardener = 'bangcle' | 'legu' | 'qihoo360';

export interface EulaInfo {
  hardener: string;
  version: string;
  text: string;
  effectiveDate: string;
}

/**
 * 各厂商 EULA 摘要(V1.5,2026-07-21)
 *
 * 核心条款统一:"本人为 APK 著作权人,本次自检系对自有资产的安全审计"
 * 完整 EULA 见 docs/compliance/audit-eula-{hardener}.md
 */
const HARDENER_EULA_TEXTS: Record<SupportedHardener, string> = {
  bangcle: `自有 APK 诊断 EULA(梆梆加固自检场景)

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

完整 EULA 见 docs/compliance/audit-eula.md`,

  legu: `自有 APK 诊断 EULA(腾讯乐固自检场景)

版本:${CURRENT_EULA_VERSION}
生效日期:2026-07-21

本人声明:
1. 待诊断 APK 是本人自有(合法著作权或授权)
2. 不绕过腾讯乐固保护(仅完整性扫描,不脱壳不反编译)
3. 不用于入侵他人系统
4. 本次自检系对自有资产的安全审计

工具能力:腾讯乐固 so 完整性报告 + API 扫描 + 签名验证(不输出源码)
禁止:脱壳 / 反编译 / 运行 APK / 处理非腾讯乐固加固

审计日志记录所有操作(含 EULA 接受状态),保留 1 年。
违反 EULA 可终止服务 + 披露违规行为。

完整 EULA 见 docs/compliance/audit-eula-legu.md`,

  qihoo360: `自有 APK 诊断 EULA(360 加固保自检场景)

版本:${CURRENT_EULA_VERSION}
生效日期:2026-07-21

本人声明:
1. 待诊断 APK 是本人自有(合法著作权或授权)
2. 不绕过 360 加固保保护(仅完整性扫描,不脱壳不反编译)
3. 不用于入侵他人系统
4. 本次自检系对自有资产的安全审计

工具能力:360 加固保 so 完整性报告 + API 扫描 + 签名验证(不输出源码)
禁止:脱壳 / 反编译 / 运行 APK / 处理非 360 加固保加固

审计日志记录所有操作(含 EULA 接受状态),保留 1 年。
违反 EULA 可终止服务 + 披露违规行为。

完整 EULA 见 docs/compliance/audit-eula-360.md`,
};

@Injectable()
export class HardenerEulaService {
  private readonly logger = new Logger(HardenerEulaService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * 获取当前 EULA 文本 + 版本号(支持多厂商)
   */
  getCurrentEula(hardener: SupportedHardener = 'bangcle'): EulaInfo {
    const text = HARDENER_EULA_TEXTS[hardener];
    if (!text) {
      throw new BadRequestException('UNSUPPORTED_HARDENER', {
        cause: `unsupported hardener for EULA: ${hardener}`,
      });
    }
    return {
      hardener,
      version: CURRENT_EULA_VERSION,
      text,
      effectiveDate: hardener === 'bangcle' ? '2026-07-20' : '2026-07-21',
    };
  }

  /**
   * 验证开发者是否已接受当前版本 EULA(支持多厂商)
   *
   * @throws ForbiddenException 未接受当前版本 EULA(EULA_REQUIRED)
   */
  async validateAccepted(
    developerId: string,
    hardener: SupportedHardener = 'bangcle',
  ): Promise<void> {
    const accepted = await this.prisma.auditLogOwn.findFirst({
      where: {
        developerId,
        eulaAccepted: true,
        eulaVersion: CURRENT_EULA_VERSION,
        hardener,
      },
      select: { id: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });

    if (!accepted) {
      throw new ForbiddenException('EULA_REQUIRED', {
        cause: `developer must accept ${hardener} EULA v${CURRENT_EULA_VERSION} before using ${hardener} hardener audit (锁 B)`,
      });
    }
  }

  /**
   * 记录开发者接受 EULA(支持多厂商)
   */
  async recordAcceptance(
    developerId: string,
    ip: string,
    userAgent?: string,
    hardener: SupportedHardener = 'bangcle',
  ): Promise<void> {
    await this.prisma.auditLogOwn.create({
      data: {
        developerId,
        appId: 'eula-accept',
        apkHash: 'n/a',
        apkSize: 0,
        packageName: 'n/a',
        signatureHash: 'n/a',
        check1Passed: true,
        check2Passed: true,
        check3Passed: true,
        status: 'SUCCESS',
        operation: 'EULA_ACCEPT',
        hardener,
        eulaVersion: CURRENT_EULA_VERSION,
        eulaAccepted: true,
        ip,
        userAgent: userAgent ?? null,
      },
    });

    this.logger.log(
      `${hardener} EULA v${CURRENT_EULA_VERSION} 已接受: developerId=${developerId}`,
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
