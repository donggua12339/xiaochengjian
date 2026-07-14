import * as crypto from 'crypto';

/**
 * 卡密生成器
 * 详见 ADR 0014 (卡密格式与生成策略)
 *
 * 格式:XXXX-XXXX-XXXX-XXXX(16 字符,4 段)
 * 字符集:32 个字母数字(去掉易混淆字符 0/O/1/I/L)
 * 最后 1 位:Luhn mod32 校验位
 * 熵:31 × log2(32) = 155 bit
 *
 * 服务端只存 SHA-256(cardKey + perCardSalt),不存明文
 */

/**
 * 字符集(32 个,去掉易混淆字符 0/O/1/I)
 * 保留 L(比 I 混淆度低),确保 32 个字符支持 Luhn mod32
 * 顺序固定,索引 0-31 对应 Luhn mod32 的数字
 */
export const CARD_CHARSET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

/**
 * 生成单张卡密明文(含 Luhn 校验位,格式 4x4)
 */
export function generateCardKey(): string {
  // 生成 15 个随机字符
  const bytes = crypto.randomBytes(15);
  const chars: string[] = [];
  for (let i = 0; i < 15; i++) {
    chars.push(CARD_CHARSET[bytes[i] % 32]);
  }

  // 计算第 16 位 Luhn mod32 校验位
  const checkDigit = luhnMod32CheckDigit(chars);
  chars.push(CARD_CHARSET[checkDigit]);

  // 格式化为 4x4:XXXX-XXXX-XXXX-XXXX
  const groups = chars.join('').match(/.{4}/g);
  return groups ? groups.join('-') : chars.join('');
}

/**
 * 验证卡密格式 + Luhn 校验位
 * @param cardKey 卡密明文(含连字符)
 * @returns 是否有效
 */
export function validateCardKey(cardKey: string): boolean {
  // 去掉连字符,转大写
  const clean = cardKey.replace(/-/g, '').toUpperCase();

  // 长度必须 16
  if (clean.length !== 16) {
    return false;
  }

  // 所有字符必须在字符集内
  for (const c of clean) {
    if (!CARD_CHARSET.includes(c)) {
      return false;
    }
  }

  // Luhn mod32 校验
  return verifyLuhnMod32(clean.split(''));
}

/**
 * 生成 perCardSalt(16 字节随机,用于哈希)
 */
export function generateCardSalt(): string {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * 计算卡密哈希:SHA-256(cardKey + salt)
 * @param cardKey 卡密明文(含或不含连字符均可)
 * @param salt perCardSalt
 */
export function hashCardKey(cardKey: string, salt: string): string {
  const clean = cardKey.replace(/-/g, '').toUpperCase();
  return crypto
    .createHash('sha256')
    .update(clean + salt)
    .digest('hex');
}

/**
 * 提取卡密前 4 位(用于后台识别,不泄露完整卡密)
 */
export function extractCardKeyPrefix(cardKey: string): string {
  return cardKey.replace(/-/g, '').substring(0, 4).toUpperCase();
}

/**
 * Luhn mod32 校验位计算
 * 标准Luhn 算法的 32 进制变体
 *
 * 算法:
 *  1. 把前 15 位字符映射到 0-31
 *  2. 从右往左,第 1 位(最右,校验位左边)乘 2,第 2 位不乘,第 3 位乘 2...
 *  3. 乘 2 后 >= 32 则减 32
 *  4. 求和
 *  5. 校验位 = (32 - sum % 32) % 32
 */
function luhnMod32CheckDigit(chars: string[]): number {
  const digits = chars.map((c) => CARD_CHARSET.indexOf(c));

  let sum = 0;
  let double = true; // 最右的字符(校验位左边第一位)要乘 2
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i];
    if (double) {
      d *= 2;
      if (d >= 32) d -= 32;
    }
    sum += d;
    double = !double;
  }

  return (32 - (sum % 32)) % 32;
}

/**
 * 验证 Luhn mod32(含校验位)
 * 验证逻辑:所有 16 位按 Luhn 规则求和,sum % 32 === 0 则有效
 */
function verifyLuhnMod32(chars: string[]): boolean {
  const digits = chars.map((c) => CARD_CHARSET.indexOf(c));

  let sum = 0;
  let double = false; // 最右(校验位)不乘 2
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i];
    if (double) {
      d *= 2;
      if (d >= 32) d -= 32;
    }
    sum += d;
    double = !double;
  }

  return sum % 32 === 0;
}
