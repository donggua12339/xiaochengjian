import { Test } from '@nestjs/testing';
import { PreflightService } from './preflight.service';
import * as fs from 'fs/promises';
import { execFile } from 'child_process';

jest.mock('fs/promises');
jest.mock('child_process');

const mockExecFile = execFile as unknown as jest.Mock;

describe('PreflightService', () => {
  let service: PreflightService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module = await Test.createTestingModule({
      providers: [PreflightService],
    }).compile();
    service = module.get(PreflightService);
  });

  describe('validateKeystore', () => {
    it('should pass when keytool succeeds and alias exists', async () => {
      mockExecFile.mockImplementation((_cmd, _args, _opts, cb: unknown) => {
        (cb as (e: Error | null, stdout: string, stderr: string) => void)(
          null,
          `别名: mykey\n条目类型: PrivateKeyEntry\n证书链长度: 1`,
          '',
        );
        return undefined;
      });

      await expect(
        service.validateKeystore('/tmp/ks.jks', 'pass123', 'mykey'),
      ).resolves.toBeUndefined();
    });

    it('should throw when keytool password is wrong', async () => {
      mockExecFile.mockImplementation(
        (_cmd: string, _args: string[], _opts: unknown, cb: unknown) => {
          (cb as (e: Error | null, stdout: string, stderr: string) => void)(
            Object.assign(new Error('keytool error'), {
              code: 1,
              stderr: 'keystore password was incorrect',
            }),
            '',
            'keystore password was incorrect',
          );
          return undefined;
        },
      );

      await expect(service.validateKeystore('/tmp/ks.jks', 'wrong', 'mykey')).rejects.toThrow(
        'Keystore 密码错误',
      );
    });

    it('should throw when alias not found', async () => {
      mockExecFile.mockImplementation(
        (_cmd: string, _args: string[], _opts: unknown, cb: unknown) => {
          (cb as (e: Error | null, stdout: string, stderr: string) => void)(
            Object.assign(new Error('alias not found'), {
              code: 1,
              stderr: 'keytool error: alias <mykey> not found',
            }),
            '',
            'keytool error: alias <mykey> not found',
          );
          return undefined;
        },
      );

      await expect(service.validateKeystore('/tmp/ks.jks', 'pass123', 'mykey')).rejects.toThrow(
        '不存在',
      );
    });
  });

  describe('validateApk', () => {
    it('should pass for valid APK', async () => {
      const fd = {
        read: jest.fn().mockImplementation((buf: Buffer) => {
          buf[0] = 0x50;
          buf[1] = 0x4b;
          buf[2] = 0x03;
          buf[3] = 0x04;
          return Promise.resolve({ bytesRead: 4 });
        }),
        close: jest.fn().mockResolvedValue(undefined),
      };
      (fs.open as jest.Mock).mockResolvedValue(fd);
      (fs.stat as jest.Mock).mockResolvedValue({ size: 18 * 1024 * 1024 });
      (fs.access as jest.Mock).mockRejectedValue(new Error('ENOENT')); // no classes-xcj.dex

      await expect(service.validateApk('/tmp/test.apk')).resolves.toBeUndefined();
    });

    it('should throw for invalid magic bytes', async () => {
      const fd = {
        read: jest.fn().mockImplementation((buf: Buffer) => {
          buf[0] = 0x00;
          buf[1] = 0x00;
          buf[2] = 0x00;
          buf[3] = 0x00;
          return Promise.resolve({ bytesRead: 4 });
        }),
        close: jest.fn().mockResolvedValue(undefined),
      };
      (fs.open as jest.Mock).mockResolvedValue(fd);
      (fs.stat as jest.Mock).mockResolvedValue({ size: 1024 });

      await expect(service.validateApk('/tmp/bad.apk')).rejects.toThrow('APK 文件损坏');
    });
  });

  describe('validateSdkArtifacts', () => {
    it('should throw when SDK DEX missing', async () => {
      (fs.stat as jest.Mock).mockRejectedValue(new Error('ENOENT'));

      await expect(service.validateSdkArtifacts()).rejects.toThrow('SDK');
    });

    it('should resolve when SDK artifact found', async () => {
      (fs.stat as jest.Mock).mockResolvedValue({ size: 100 });
      await expect(service.validateSdkArtifacts()).resolves.toBeUndefined();
    });
  });

  describe('validateApk 已加固检测', () => {
    it('含 classes-xcj.dex 应抛"已加固"', async () => {
      const AdmZip = (await import('adm-zip')).default;
      const os = await import('os');
      const pathMod = await import('path');
      const tmpApk = pathMod.join(os.tmpdir(), `preflight-test-${Date.now()}.apk`);
      const zip = new AdmZip();
      zip.addFile('classes.dex', Buffer.from('dex'));
      zip.addFile('classes-xcj.dex', Buffer.from('xcj-dex'));
      zip.writeZip(tmpApk);

      (fs.stat as jest.Mock).mockResolvedValue({ size: 5000 });
      const fd = {
        read: jest.fn().mockImplementation((buf: Buffer) => {
          buf[0] = 0x50;
          buf[1] = 0x4b;
          buf[2] = 0x03;
          buf[3] = 0x04;
          return Promise.resolve({ bytesRead: 4 });
        }),
        close: jest.fn().mockResolvedValue(undefined),
      };
      (fs.open as jest.Mock).mockResolvedValue(fd);

      await expect(service.validateApk(tmpApk)).rejects.toThrow('已加固');
    });
  });

  describe('validateKeystore keytool 边界', () => {
    it('keytool 输出含 error 但非密码错误不应误判为密码错', async () => {
      mockExecFile.mockImplementation(
        (_cmd: string, _args: string[], _opts: unknown, cb: unknown) => {
          (cb as (e: null, stdout: string, stderr: string) => void)(
            null,
            'some generic error text',
            '',
          );
          return undefined;
        },
      );
      await expect(
        service.validateKeystore('/tmp/ks.jks', 'pass', 'alias'),
      ).resolves.toBeUndefined();
    });
  });

  describe('runAll', () => {
    it('should run all preflight checks', async () => {
      // keytool mock
      mockExecFile.mockImplementation((_cmd, _args, _opts, cb: unknown) => {
        (cb as (e: Error | null, stdout: string, stderr: string) => void)(
          null,
          `别名: mykey\n条目类型: PrivateKeyEntry`,
          '',
        );
        return undefined;
      });

      // APK mock
      const fd = {
        read: jest.fn().mockImplementation((buf: Buffer) => {
          buf[0] = 0x50;
          buf[1] = 0x4b;
          buf[2] = 0x03;
          buf[3] = 0x04;
          return Promise.resolve({ bytesRead: 4 });
        }),
        close: jest.fn().mockResolvedValue(undefined),
      };
      (fs.open as jest.Mock).mockResolvedValue(fd);
      (fs.stat as jest.Mock).mockResolvedValue({ size: 18 * 1024 * 1024 });
      (fs.access as jest.Mock).mockRejectedValue(new Error('ENOENT'));

      // runAll should not throw
      await expect(
        service.runAll('/tmp/test.apk', '/tmp/ks.jks', 'pass123', 'mykey'),
      ).resolves.toBeUndefined();
    });
  });
});
