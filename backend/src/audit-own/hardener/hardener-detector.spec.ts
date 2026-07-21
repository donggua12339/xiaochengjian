import { ForbiddenException } from '@nestjs/common';
import { HardenerDetector } from './hardener-detector';

/**
 * HardenerDetector 单元测试(ADR 0078 锁 A:仅梆梆一家)
 *
 * 覆盖:
 *  - 检测到梆梆 so -> hardener=bangcle
 *  - 检测到梆梆 Application 类名前缀 -> hardener=bangcle
 *  - 检测到 360/爱加密/乐固/百度 so -> 抛 UNSUPPORTED_HARDENER
 *  - 无加固特征 -> hardener=null
 *  - 同时有梆梆 + 360 -> 抛 UNSUPPORTED_HARDENER(锁 A 优先拒绝)
 */
describe('HardenerDetector', () => {
  let detector: HardenerDetector;

  beforeEach(() => {
    detector = new HardenerDetector();
  });

  it('检测到 libSecShell.so 应返回 bangcle', () => {
    const result = detector.detect(['lib/arm64-v8a/libSecShell.so']);
    expect(result.hardener).toBe('bangcle');
    expect(result.evidence).toContain('so: lib/arm64-v8a/libSecShell.so');
  });

  it('检测到 libDexHelper.so 应返回 bangcle', () => {
    // 注:libDexHelper.so 同时在梆梆和顶象特征里,梆梆优先匹配
    const result = detector.detect(['lib/armeabi-v7a/libDexHelper.so']);
    expect(result.hardener).toBe('bangcle');
  });

  it('检测到 libNative.so 应返回 bangcle', () => {
    const result = detector.detect(['lib/x86_64/libNative.so']);
    expect(result.hardener).toBe('bangcle');
  });

  it('检测到梆梆 Application 类名前缀(com.bangcle.*)应返回 bangcle', () => {
    const result = detector.detect([], 'com.bangcle.test.MainApplication');
    expect(result.hardener).toBe('bangcle');
    expect(result.evidence).toContain('applicationClass: com.bangcle.test.MainApplication');
  });

  it('检测到梆梆 Application 类名前缀(com.secapk.*)应返回 bangcle', () => {
    const result = detector.detect([], 'com.secapk.wrapper.Application');
    expect(result.hardener).toBe('bangcle');
  });

  // V1.5 扩展:360 加固保 + 腾讯乐固(ADR 0082-A/B)

  it('检测到 360 加固 so(libjiagu.so)应返回 qihoo360', () => {
    const result = detector.detect(['lib/arm64-v8a/libjiagu.so']);
    expect(result.hardener).toBe('qihoo360');
  });

  it('检测到腾讯乐固 so(libshell.so)应返回 legu', () => {
    const result = detector.detect(['lib/arm64-v8a/libshell.so']);
    expect(result.hardener).toBe('legu');
  });

  it('检测到腾讯乐固 so(libshella.so)应返回 legu', () => {
    const result = detector.detect(['lib/armeabi-v7a/libshella.so']);
    expect(result.hardener).toBe('legu');
  });

  it('检测到 360 Application 类名(com.qihoo.*)应返回 qihoo360', () => {
    const result = detector.detect([], 'com.qihoo.util.QihooApplication');
    expect(result.hardener).toBe('qihoo360');
  });

  it('检测到腾讯 Application 类名(com.tencent.*)应返回 legu', () => {
    const result = detector.detect([], 'com.tencent.tauth.TencentApplication');
    expect(result.hardener).toBe('legu');
  });

  it('检测到爱加密 so 应抛 UNSUPPORTED_HARDENER', () => {
    expect(() => detector.detect(['lib/armeabi-v7a/libexec.so'])).toThrow(
      ForbiddenException,
    );
  });

  it('检测到百度加固 so 应抛 UNSUPPORTED_HARDENER', () => {
    expect(() => detector.detect(['lib/arm64-v8a/libbaiduprotect.so'])).toThrow(
      ForbiddenException,
    );
  });

  it('同时有梆梆 + 360 so 应返回 bangcle(梆梆优先)', () => {
    const result = detector.detect([
      'lib/arm64-v8a/libSecShell.so',
      'lib/arm64-v8a/libjiagu.so',
    ]);
    expect(result.hardener).toBe('bangcle');
  });

  it('无加固特征应返回 null', () => {
    const result = detector.detect([
      'classes.dex',
      'AndroidManifest.xml',
      'resources.arsc',
      'lib/arm64-v8a/libmyown.so',
    ]);
    expect(result.hardener).toBeNull();
    expect(result.evidence).toBeUndefined();
  });

  it('空 entry 列表应返回 null', () => {
    const result = detector.detect([]);
    expect(result.hardener).toBeNull();
  });

  it('非加固 Application 类名(如 com.example.*)应返回 null', () => {
    const result = detector.detect([], 'com.example.myapp.Application');
    expect(result.hardener).toBeNull();
  });

  describe('真实梆梆样本(logo设计制作.apk,2026-07-20 验证)', () => {
    // 样本来源:用户提供,已梆梆加固(含 libSecShell.so)
    // 注:样本含 msa OAID SDK(libmsaoaidsec.so / libmsaoaidauth.so)+ libanti_break_debug.so,
    //     这些不在梆梆特征列表也不在不支持厂商列表,不应影响检测
    const realBangcleEntries = [
      'lib/arm64-v8a/libCtaApiLib.so',
      'lib/arm64-v8a/libanti_break_debug.so',
      'lib/arm64-v8a/libdevInfo.so',
      'lib/arm64-v8a/libmsaoaidauth.so',
      'lib/arm64-v8a/libmsaoaidsec.so',
      'lib/armeabi-v7a/libCtaApiLib.so',
      'lib/armeabi-v7a/libanti_break_debug.so',
      'lib/armeabi-v7a/libdevInfo.so',
      'lib/armeabi-v7a/libmsaoaidauth.so',
      'lib/armeabi-v7a/libmsaoaidsec.so',
      'lib/armeabi/libCtaApiLib.so',
      'lib/x86/libCtaApiLib.so',
      'lib/x86/libanti_break_debug.so',
      'lib/x86/libdevInfo.so',
      'lib/x86/libmsaoaidauth.so',
      'lib/x86/libmsaoaidsec.so',
      'lib/x86_64/libCtaApiLib.so',
      'lib/x86_64/libanti_break_debug.so',
      'lib/x86_64/libdevInfo.so',
      'lib/x86_64/libmsaoaidauth.so',
      'lib/x86_64/libmsaoaidsec.so',
      // 梆梆加固 so(5 个 ABI 全覆盖)
      'lib/armeabi-v7a/libSecShell.so',
      'lib/x86/libSecShell.so',
      'lib/arm64-v8a/libSecShell.so',
      'lib/x86_64/libSecShell.so',
      'lib/armeabi/libSecShell.so',
      // 梆梆加固把原 dex 加密放 assets
      'assets/classes0.jar',
      'classes.dex',
      'AndroidManifest.xml',
    ];

    it('应识别为 bangcle(锁 A 通过)', () => {
      const result = detector.detect(realBangcleEntries);
      expect(result.hardener).toBe('bangcle');
      expect(result.evidence).toBeDefined();
      expect(result.evidence?.length).toBeGreaterThan(0);
    });

    it('不应误判 msa OAID SDK(libmsaoaidsec.so)为不支持的加固厂商', () => {
      // 关键:libmsaoaidsec.so 含 "sec" 但不是 libshell.so/libjiagu.so,不应触发 UNSUPPORTED
      // 检测应正常返回 bangcle,不抛 ForbiddenException
      const result = detector.detect(realBangcleEntries);
      expect(result.hardener).toBe('bangcle');
    });

    it('不应误判 libanti_break_debug.so 为不支持的加固厂商', () => {
      // 反调试 so,名称含 "debug" 但不在不支持列表
      const result = detector.detect(realBangcleEntries);
      expect(result.hardener).toBe('bangcle');
    });

    it('梆梆证据应含 libSecShell.so(5 个 ABI)', () => {
      const result = detector.detect(realBangcleEntries);
      expect(result.hardener).toBe('bangcle');
      // evidence 应含 libSecShell.so 的匹配
      const secShellEvidence = result.evidence?.filter((e) =>
        e.includes('libSecShell.so'),
      );
      expect(secShellEvidence?.length).toBeGreaterThan(0);
    });
  });
});
