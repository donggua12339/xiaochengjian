import { BadRequestException } from '@nestjs/common';
import { IntegrityController } from './integrity.controller';
import { IntegrityService } from './integrity.service';

describe('IntegrityController', () => {
  let controller: IntegrityController;
  let integrityService: { verifyAndIssueToken: jest.Mock; verifyToken: jest.Mock };

  beforeEach(() => {
    integrityService = {
      verifyAndIssueToken: jest.fn().mockResolvedValue({ verdict: 'PASS', token: 'tok' }),
      verifyToken: jest.fn().mockReturnValue({ valid: true, appId: 'com.test' }),
    };
    controller = new IntegrityController(integrityService as unknown as IntegrityService);
  });

  const validBody = {
    appId: 'com.test',
    encryptedHash: 'aGFzaA==',
    nonce: 'n',
    timestamp: Date.now(),
  };

  describe('verify', () => {
    it('缺必填字段应抛 MISSING_REQUIRED_FIELDS', async () => {
      await expect(controller.verify('dev-1', { ...validBody, appId: '' })).rejects.toThrow(
        BadRequestException,
      );
      await expect(controller.verify('dev-1', { ...validBody, nonce: '' })).rejects.toThrow(
        BadRequestException,
      );
    });

    it('合法请求应委托并附加 developerId', async () => {
      const r = await controller.verify('dev-1', validBody);
      expect(integrityService.verifyAndIssueToken).toHaveBeenCalledWith(
        expect.objectContaining({ appId: 'com.test' }),
      );
      expect(r.developerId).toBe('dev-1');
      expect(r.verdict).toBe('PASS');
    });
  });

  describe('verifyToken', () => {
    it('缺 token 应抛 TOKEN_REQUIRED', async () => {
      await expect(controller.verifyToken({ token: '' })).rejects.toThrow(BadRequestException);
    });

    it('合法 token 应委托 service', async () => {
      const r = await controller.verifyToken({ token: 'abc' });
      expect(integrityService.verifyToken).toHaveBeenCalledWith('abc');
      expect(r.valid).toBe(true);
    });
  });
});
