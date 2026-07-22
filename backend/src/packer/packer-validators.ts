import { Injectable, ForbiddenException, BadRequestException, Logger } from '@nestjs/common';
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
  // SDK v0.2.0 classes-xcj.dex SHA-256(2026-07-21 编译)
  'd624e2a9243ffbb9e5b3e6ada5ce8e05ec993580a253f9a01090b9e60ae462be',
];

/**
 * xcj-defender-sdk 编译产物 classes-defender.dex 的 SHA-256 白名单(ADR 0088)
 *
 * 与 XCJ_AUTH_SDK_DEX_WHITELIST 独立,每次 defender-sdk 版本更新时同步。
 * 当前 v1.0.0 的 classes-defender.dex hash(2026-07-22 编译)
 */
export const XCJ_DEFENDER_SDK_DEX_WHITELIST: string[] = [
  // defender-sdk classes-defender.dex SHA-256(2026-07-22 编译,v1.0.0,d8 转换)
  'b6411e45fb1478ca4d2cda5831745e8b8020d96e769d698e67db48c5038c15e1',
];

/**
 * xcj-defender-sdk .aar 的 SHA-256 白名单(ADR 0088)
 *
 * 锁 2 扩展:defender-sdk .so 来自固定 .aar,校验 .aar 整体 hash。
 * 与 dex 白名单独立(.aar 含 .so + classes.jar,整体校验更严格)。
 */
export const XCJ_DEFENDER_SDK_AAR_WHITELIST: string[] = [
  // defender-sdk .aar SHA-256(2026-07-22 编译,v1.0.0)
  '1351da48f0e96d3d07265223b36cbac42ecf0107d79392f3c48fab20c4d415a3',
];

/**
 * Manifest 允许修改的标签白名单(锁 3)
 *
 * 仅允许:
 *  - <application android:name="...">(改为 XcjApplication 或委托)
 *  - <meta-data android:name="xcj.*" />(SDK 配置,含 xcj.defender.*)
 *  - <uses-permission android:name="android.permission.INTERNET" />(SDK 必需)
 *  - <provider android:name="com.xcj.defender.DefenderInitProvider" />(ADR 0088 扩展)
 *
 * 不允许:
 *  - 修改 Activity/Service/Receiver 类名或属性
 *  - 添加新组件(除 DefenderInitProvider 外)
 *  - 修改 intent-filter
 *  - 修改 UI 属性(theme/label/icon)
 */
export const MANIFEST_ALLOWED_CHANGES = {
  applicationName: true, // 改 <application android:name>
  metaData: /^xcj\./, // <meta-data android:name="xcj.*">(含 xcj.defender.*)
  permissions: ['android.permission.INTERNET'], // 允许添加的权限
  defenderProvider: 'com.xcj.defender.DefenderInitProvider', // ADR 0088 扩展:允许注册 DefenderInitProvider
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
    const matched = app.signHashAllowList.some((h) => h.toLowerCase() === normalized);
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
    const matched = XCJ_AUTH_SDK_DEX_WHITELIST.some((h) => h.toLowerCase() === normalized);
    if (!matched) {
      throw new ForbiddenException('CONTENT_LOCK_FAILED', {
        cause: 'injected dex hash not in xcj-auth-sdk whitelist (锁 2 内容锁定)',
      });
    }
  }

  /**
   * 锁 2 扩展:defender-sdk dex 内容锁定(ADR 0088)
   *
   * 与 validateContentLock 独立,校验 classes-defender.dex 的 SHA-256。
   *
   * @param injectedDefenderDexHash 注入的 classes-defender.dex SHA-256
   * @throws ForbiddenException 注入内容不在 defender 白名单
   */
  validateDefenderContentLock(injectedDefenderDexHash: string): void {
    if (XCJ_DEFENDER_SDK_DEX_WHITELIST.length === 0) {
      this.logger.warn('锁 2 扩展:defender dex 白名单为空,跳过校验(MVP,待首次编译后填入)');
      return;
    }
    const normalized = injectedDefenderDexHash.toLowerCase();
    const matched = XCJ_DEFENDER_SDK_DEX_WHITELIST.some((h) => h.toLowerCase() === normalized);
    if (!matched) {
      throw new ForbiddenException('DEFENDER_CONTENT_LOCK_FAILED', {
        cause: 'injected defender dex hash not in xcj-defender-sdk whitelist (锁 2 扩展)',
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
    defenderProviderAdded: boolean;
    otherChanges: string[];
  }): void {
    const {
      applicationNameChanged,
      metaDataAdded,
      permissionsAdded,
      defenderProviderAdded,
      otherChanges,
    } = manifestChanges;

    // 不允许其他修改
    if (otherChanges.length > 0) {
      throw new ForbiddenException('ENTRY_LOCK_FAILED', {
        cause: `disallowed manifest changes: ${otherChanges.join(', ')} (锁 3 入口锁定)`,
      });
    }

    // Meta-data 必须以 xcj. 开头(含 xcj.defender.*)
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
    // defenderProviderAdded 允许(ADR 0088 扩展,仅 DefenderInitProvider)
    void defenderProviderAdded;
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
      'contacts',
      'location',
      'sms',
      'callLog',
      'phone',
      'imei',
      'serialNumber',
      'macAddress',
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
