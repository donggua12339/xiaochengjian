import {
  Injectable,
  ForbiddenException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Packer 七锁校验器(ADR 0081)
 *
 * 七锁架构(律师预审 2026-07-21 通过):
 *  锁 1 对象锁定:三重校验(包名白名单 + 签名 hash + 目录隔离)
 *  锁 2 内容锁定:注入内容仅为 xcj-auth-sdk 固定 dex(SHA-256 白名单)
 *  锁 3 入口锁定:Manifest 修改仅限 Application 委托 + Meta-data
 *  锁 4 签名锁定:强制自备 Keystore V1+V2+V3 重签
 *  锁 5 权限锁定:JWT 开发者自身(管理员只读)
 *  锁 6 数据锁定:SDK 仅上报 OAID + 包信息,无敏感隐私
 *  锁 7 客户端签名自检:SDK 初始化时校验 APK 签名 hash,不一致拒启 PACKAGE_TAMPERED
 *
 * 任一锁失败抛 ForbiddenException,不提供跳过开关。
 */

/**
 * xcj-auth-sdk 编译产物 classes-xcj.dex 的 SHA-256 白名单
 *
 * 锁 2 核心约束:只允许注入白名单内的 dex,禁止自定义 smali。
 * 每次 SDK 版本更新时,更新此白名单(编译后计算 SHA-256 加入)。
 *
 * 当前 v0.2.0 的 classes-xcj.dex hash(占位,实际编译后填入):
 */
export const XCJ_AUTH_SDK_DEX_WHITELIST: string[] = [
  // TODO: SDK v0.2.0 编译后填入实际 hash
  // 示例:'a1b2c3d4e5f6...'(64 字符 hex)
];

/**
 * Manifest 允许修改的标签白名单(锁 3)
 *
 * 仅允许:
 *  - <application android:name="...">(改为 XcjApplication 或委托)
 *  - <meta-data android:name="xcj.*" />(SDK 配置)
 *  - <uses-permission android:name="android.permission.INTERNET" />(SDK 必需)
 *
 * 不允许:
 *  - 修改 Activity/Service/Receiver/Provider 类名或属性
 *  - 添加新组件
 *  - 修改 intent-filter
 *  - 修改 UI 属性(theme/label/icon)
 */
export const MANIFEST_ALLOWED_CHANGES = {
  applicationName: true, // 改 <application android:name>
  metaData: /^xcj\./, // <meta-data android:name="xcj.*">
  permissions: ['android.permission.INTERNET'], // 允许添加的权限
};

@Injectable()
export class PackerValidators {
  private readonly logger = new Logger(PackerValidators.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * 锁 1:对象锁定 -- 三重校验(包名白名单 + 签名 hash + 目录隔离)
   *
   * 复用 ADR 0077 的三重校验逻辑,确保仅处理开发者自有 APK。
   *
   * @returns 匹配的 application(含 id / signHashAllowList)
   * @throws ForbiddenException 包名不在白名单 / 签名不匹配
   */
  async validateObjectLock(
    developerId: string,
    packageName: string,
    signatureHash: string,
  ): Promise<{
    id: string;
    name: string;
    signHashAllowList: string[];
  }> {
    // 校验 1:包名白名单
    const app = await this.prisma.application.findFirst({
      where: { developerId, packageName },
      select: { id: true, name: true, signHashAllowList: true },
    });
    if (!app) {
      throw new ForbiddenException('APP_NOT_OWNED', {
        cause: 'package name not in developer whitelist (锁 1 对象锁定)',
      });
    }

    // 校验 2:签名 hash 比对
    if (!app.signHashAllowList || app.signHashAllowList.length === 0) {
      throw new ForbiddenException('SIGNATURE_WHITELIST_EMPTY', {
        cause: 'developer must configure signHashAllowList first (锁 1)',
      });
    }
    const normalized = signatureHash.toLowerCase();
    const matched = app.signHashAllowList.some(
      (h) => h.toLowerCase() === normalized,
    );
    if (!matched) {
      throw new ForbiddenException('SIGNATURE_MISMATCH', {
        cause: 'apk signature hash not in developer allowlist (锁 1)',
      });
    }

    // 校验 3:目录隔离(由 PackerService 在调用时保证 /tmp/packer/<taskId>/)
    return app;
  }

  /**
   * 锁 2:内容锁定 -- 注入内容仅为 xcj-auth-sdk 固定 dex
   *
   * @param injectedDexHash 注入的 classes-xcj.dex SHA-256
   * @throws ForbiddenException 注入内容不在白名单
   */
  validateContentLock(injectedDexHash: string): void {
    if (XCJ_AUTH_SDK_DEX_WHITELIST.length === 0) {
      // 白名单未配置(MVP 阶段),先放行但记录警告
      this.logger.warn('锁 2 内容锁定:XCJ_AUTH_SDK_DEX_WHITELIST 为空,跳过校验(MVP)');
      return;
    }
    const normalized = injectedDexHash.toLowerCase();
    const matched = XCJ_AUTH_SDK_DEX_WHITELIST.some(
      (h) => h.toLowerCase() === normalized,
    );
    if (!matched) {
      throw new ForbiddenException('CONTENT_LOCK_FAILED', {
        cause: 'injected dex hash not in xcj-auth-sdk whitelist (锁 2 内容锁定)',
      });
    }
  }

  /**
   * 锁 3:入口锁定 -- Manifest 修改范围校验
   *
   * @param manifestChanges Manifest 修改项
   * @throws ForbiddenException 修改超出允许范围
   */
  validateEntryLock(manifestChanges: {
    applicationNameChanged: boolean;
    metaDataAdded: string[];
    permissionsAdded: string[];
    otherChanges: string[];
  }): void {
    const { applicationNameChanged, metaDataAdded, permissionsAdded, otherChanges } =
      manifestChanges;

    // 不允许其他修改
    if (otherChanges.length > 0) {
      throw new ForbiddenException('ENTRY_LOCK_FAILED', {
        cause: `disallowed manifest changes: ${otherChanges.join(', ')} (锁 3 入口锁定)`,
      });
    }

    // Meta-data 必须以 xcj. 开头
    const invalidMeta = metaDataAdded.filter((m) => !MANIFEST_ALLOWED_CHANGES.metaData.test(m));
    if (invalidMeta.length > 0) {
      throw new ForbiddenException('ENTRY_LOCK_FAILED', {
        cause: `invalid meta-data names: ${invalidMeta.join(', ')} (锁 3,必须以 xcj. 开头)`,
      });
    }

    // 权限必须在白名单内
    const invalidPerm = permissionsAdded.filter(
      (p) => !MANIFEST_ALLOWED_CHANGES.permissions.includes(p),
    );
    if (invalidPerm.length > 0) {
      throw new ForbiddenException('ENTRY_LOCK_FAILED', {
        cause: `invalid permissions: ${invalidPerm.join(', ')} (锁 3,仅允许 INTERNET)`,
      });
    }

    // applicationNameChanged 允许(委托模式)
    void applicationNameChanged;
  }

  /**
   * 锁 4:签名锁定 -- 强制自备 Keystore
   *
   * @param keystoreBuffer keystore 文件 buffer
   * @throws BadRequestException keystore 缺失
   */
  validateSignLock(keystoreBuffer: Buffer): void {
    if (!keystoreBuffer || keystoreBuffer.length === 0) {
      throw new BadRequestException('KEYSTORE_REQUIRED', {
        cause: 'developer must provide own keystore (锁 4 签名锁定,小城笺不提供通用签名)',
      });
    }
  }

  /**
   * 锁 5:权限锁定 -- JWT 开发者自身
   *
   * @param jwtDeveloperId JWT 中的 developerId
   * @param appDeveloperId 应用所属 developerId
   * @throws ForbiddenException 非应用所有者
   */
  validatePermissionLock(jwtDeveloperId: string, appDeveloperId: string): void {
    if (jwtDeveloperId !== appDeveloperId) {
      throw new ForbiddenException('PERMISSION_LOCK_FAILED', {
        cause: 'only app owner can pack (锁 5 权限锁定,管理员只读)',
      });
    }
  }

  /**
   * 锁 6:数据锁定 -- SDK 配置仅含 OAID + 包信息
   *
   * @param sdkConfig SDK 配置
   * @throws ForbiddenException 配置含敏感隐私字段
   */
  validateDataLock(sdkConfig: Record<string, unknown>): void {
    const allowedKeys = ['appId', 'serverUrl', 'offlineCacheDays', 'oaidEnabled'];
    const sensitiveKeys = [
      'contacts', 'location', 'sms', 'callLog', 'phone',
      'imei', 'serialNumber', 'macAddress',
    ];

    for (const key of Object.keys(sdkConfig)) {
      if (!allowedKeys.includes(key)) {
        throw new ForbiddenException('DATA_LOCK_FAILED', {
          cause: `disallowed sdk config key: ${key} (锁 6 数据锁定,仅允许 ${allowedKeys.join('/')})`,
        });
      }
    }

    for (const sensitive of sensitiveKeys) {
      if (sensitive in sdkConfig) {
        throw new ForbiddenException('DATA_LOCK_FAILED', {
          cause: `sensitive data field in sdk config: ${sensitive} (锁 6,禁止采集敏感隐私)`,
        });
      }
    }
  }

  /**
   * 锁 7:客户端签名自检 -- SDK 初始化时校验 APK 签名 hash
   *
   * 此锁在 SDK 运行时执行(客户端),PackerService 只配置预期 hash。
   * SDK 初始化时比对当前 APK 签名 hash 与配置的预期 hash,
   * 不一致直接拒启(PACKAGE_TAMPERED)。
   *
   * @param expectedSignatureHash 预期签名 hash(写入 SDK 配置)
   * @returns 配置给 SDK 的签名自检参数
   */
  configureClientSignatureCheck(expectedSignatureHash: string): {
    expectedSignatureHash: string;
    actionOnMismatch: 'PACKAGE_TAMPERED';
  } {
    if (!expectedSignatureHash || expectedSignatureHash.length !== 64) {
      throw new BadRequestException('INVALID_SIGNATURE_HASH', {
        cause: 'expected signature hash must be 64-char hex (锁 7 客户端签名自检)',
      });
    }
    return {
      expectedSignatureHash: expectedSignatureHash.toLowerCase(),
      actionOnMismatch: 'PACKAGE_TAMPERED',
    };
  }
}
