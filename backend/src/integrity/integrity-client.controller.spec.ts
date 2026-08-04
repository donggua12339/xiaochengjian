import { BadRequestException } from '@nestjs/common';
import { IntegrityClientController } from './integrity-client.controller';
import { IntegrityService } from './integrity.service';

describe('IntegrityClientController', () => {
  let controller: IntegrityClientController;
  let integrityService: { verifyAndIssueToken: jest.Mock };

  beforeEach(() => {
    integrityService = {
      verifyAndIssueToken: jest.fn().mockResolvedValue({ verdict: 'PASS', token: 'tok' }),
    };
    controller = new IntegrityClientController(integrityService as unknown as IntegrityService);
  });

  const validBody = {
    appId: 'com.test',
    encryptedHash: 'aGFzaA==',
    nonce: 'n',
    timestamp: Date.now(),
  };

  it('缺必填字段应抛 MISSING_REQUIRED_FIELDS', async () => {
    await expect(controller.clientVerify({ ...validBody, encryptedHash: '' })).rejects.toThrow(
      BadRequestException,
    );
    await expect(controller.clientVerify({ ...validBody, timestamp: 0 })).rejects.toThrow(
      BadRequestException,
    );
  });

  it('合法请求应委托 verifyAndIssueToken', async () => {
    const r = await controller.clientVerify(validBody);
    expect(integrityService.verifyAndIssueToken).toHaveBeenCalledWith(
      expect.objectContaining({ appId: 'com.test', nonce: 'n' }),
    );
    expect(r.verdict).toBe('PASS');
  });

  it('应透传 deviceFingerprint', async () => {
    await controller.clientVerify({ ...validBody, deviceFingerprint: 'fp-1' });
    expect(integrityService.verifyAndIssueToken).toHaveBeenCalledWith(
      expect.objectContaining({ deviceFingerprint: 'fp-1' }),
    );
  });
});
