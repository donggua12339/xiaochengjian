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

  it('检测到 360 加固 so 应抛 UNSUPPORTED_HARDENER', () => {
    expect(() => detector.detect(['lib/arm64-v8a/libjiagu.so'])).toThrow(
      ForbiddenException,
    );
  });

  it('检测到爱加密 so 应抛 UNSUPPORTED_HARDENER', () => {
    expect(() => detector.detect(['lib/armeabi-v7a/libexec.so'])).toThrow(
      ForbiddenException,
    );
  });

  it('检测到腾讯乐固 so 应抛 UNSUPPORTED_HARDENER', () => {
    expect(() => detector.detect(['lib/arm64-v8a/libshell.so'])).toThrow(
      ForbiddenException,
    );
  });

  it('检测到百度加固 so 应抛 UNSUPPORTED_HARDENER', () => {
    expect(() => detector.detect(['lib/arm64-v8a/libbaiduprotect.so'])).toThrow(
      ForbiddenException,
    );
  });

  it('同时有梆梆 + 360 so 应抛 UNSUPPORTED_HARDENER(锁 A 优先拒绝)', () => {
    expect(() =>
      detector.detect([
        'lib/arm64-v8a/libSecShell.so',
        'lib/arm64-v8a/libjiagu.so',
      ]),
    ).toThrow(ForbiddenException);
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

  it('非梆梆 Application 类名(如 com.tencent.*)不应识别为 bangcle', () => {
    const result = detector.detect([], 'com.tencent.tauth.TencentApplication');
    expect(result.hardener).toBeNull();
  });
});
