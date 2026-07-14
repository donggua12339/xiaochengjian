import {
  generateCardKey,
  generateCardSalt,
  hashCardKey,
  extractCardKeyPrefix,
  validateCardKey,
  CARD_CHARSET,
} from './card-key-generator';

describe('card-key-generator', () => {
  describe('generateCardKey', () => {
    it('应生成 4x4 格式(16 字符 + 3 连字符)', () => {
      const key = generateCardKey();
      expect(key).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    });

    it('应通过格式校验(含 Luhn)', () => {
      for (let i = 0; i < 100; i++) {
        const key = generateCardKey();
        expect(validateCardKey(key)).toBe(true);
      }
    });

    it('每次生成应不同(随机性)', () => {
      const keys = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        keys.add(generateCardKey());
      }
      expect(keys.size).toBeGreaterThan(990);
    });

    it('不应包含易混淆字符(0/O/1/I)', () => {
      for (let i = 0; i < 100; i++) {
        const key = generateCardKey();
        const chars = key.replace(/-/g, '');
        for (const c of chars) {
          expect(CARD_CHARSET).toContain(c);
          expect(['0', 'O', '1', 'I']).not.toContain(c);
        }
      }
    });
  });

  describe('validateCardKey', () => {
    it('正确格式应通过', () => {
      const key = generateCardKey();
      expect(validateCardKey(key)).toBe(true);
    });

    it('小写应通过(自动转大写)', () => {
      const key = generateCardKey().toLowerCase();
      expect(validateCardKey(key)).toBe(true);
    });

    it('格式错误应拒绝', () => {
      expect(validateCardKey('ABC-DEF')).toBe(false);
      expect(validateCardKey('ABCDEFGHIJKLMNOP')).toBe(false);
      expect(validateCardKey('ABCD-EFGH-IJKL-MNO1')).toBe(false);
      expect(validateCardKey('')).toBe(false);
    });

    it('篡改后应不通过 Luhn', () => {
      const key = generateCardKey();
      const firstChar = key[0];
      const otherChar = [...CARD_CHARSET].find((c) => c !== firstChar)!;
      const tampered = otherChar + key.slice(1);
      expect(validateCardKey(tampered)).toBe(false);
    });
  });

  describe('generateCardSalt', () => {
    it('应生成 32 字符十六进制盐', () => {
      const salt = generateCardSalt();
      expect(salt).toMatch(/^[0-9a-f]{32}$/);
    });

    it('每次应不同', () => {
      const salts = new Set<string>();
      for (let i = 0; i < 100; i++) {
        salts.add(generateCardSalt());
      }
      expect(salts.size).toBe(100);
    });
  });

  describe('hashCardKey', () => {
    it('应返回 64 字符十六进制 SHA-256', () => {
      const hash = hashCardKey('ABCD-EFGH-IJKL-MNOP', 'abcdef0123456789abcdef0123456789');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('相同输入应相同输出(确定性)', () => {
      const key = 'ABCD-EFGH-IJKL-MNOP';
      const salt = 'abcdef0123456789abcdef0123456789';
      expect(hashCardKey(key, salt)).toBe(hashCardKey(key, salt));
    });

    it('不同盐应不同 hash', () => {
      const key = 'ABCD-EFGH-IJKL-MNOP';
      const salt1 = 'abcdef0123456789abcdef0123456789';
      const salt2 = '0123456789abcdef0123456789abcdef';
      expect(hashCardKey(key, salt1)).not.toBe(hashCardKey(key, salt2));
    });

    it('不同卡密应不同 hash', () => {
      const salt = 'abcdef0123456789abcdef0123456789';
      expect(hashCardKey('ABCD-EFGH-IJKL-MNOP', salt)).not.toBe(
        hashCardKey('ABCD-EFGH-IJKL-MNQR', salt),
      );
    });
  });

  describe('extractCardKeyPrefix', () => {
    it('应返回前 4 位(不含连字符)', () => {
      expect(extractCardKeyPrefix('ABCD-EFGH-IJKL-MNOP')).toBe('ABCD');
    });

    it('应自动转大写', () => {
      expect(extractCardKeyPrefix('abcd-efgh-ijkl-mnop')).toBe('ABCD');
    });
  });
});
