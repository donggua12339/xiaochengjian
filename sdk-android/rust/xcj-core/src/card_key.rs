//! 卡密格式校验模块(M2.3 实现)
//!
//! 详见 ADR 0014 (卡密格式:4x4 字母数字 + Luhn mod32 校验)
//!
//! 与后端 `backend/src/card-key/card-key-generator.ts` 算法一致
//! 客户端预校验:格式错误直接拒绝,省一次网络请求

/// 字符集:32 字符(去掉 0/O/1/I,保留 L 凑 2^5 便于 mod 运算)
pub const CARD_CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// 校验卡密格式 + Luhn mod32
///
/// # 参数
/// - `card_key`: 卡密明文,如 "ABCD-EFGH-IJKL-MNOP"
///
/// # 返回
/// - `true`: 格式正确 + Luhn 校验通过
/// - `false`: 格式错误或校验失败
pub fn validate_card_key(card_key: &str) -> bool {
    let normalized = card_key.trim().to_uppercase();
    let normalized = normalized.replace('-', "");

    // 必须是 16 字符
    if normalized.len() != 16 {
        return false;
    }

    // 每个字符必须在字符集内
    let chars: Vec<u8> = normalized.bytes().collect();
    for c in &chars {
        if CARD_CHARSET.iter().all(|&x| x != *c) {
            return false;
        }
    }

    // Luhn mod32 校验
    verify_luhn_mod32(&chars)
}

/// Luhn mod32 校验
///
/// 算法:
/// 1. 每个字符映射到 0-31(字符集索引)
/// 2. 从右往左,校验位(第 16 位)视为 0
/// 3. 第 15, 13, 11, ... 位(从右数第 2, 4, 6, ... 位)乘 2
/// 4. 乘 2 后 >= 32 则减 32
/// 5. 求和
/// 6. sum % 32 == 0 则校验通过
fn verify_luhn_mod32(chars: &[u8]) -> bool {
    let digits: Vec<usize> = chars
        .iter()
        .map(|c| CARD_CHARSET.iter().position(|&x| x == *c).unwrap_or(usize::MAX))
        .collect();

    if digits.iter().any(|&d| d == usize::MAX) {
        return false;
    }

    let mut sum = 0usize;
    let mut double = false; // 校验位(最右)不乘 2

    for &d in digits.iter().rev() {
        let mut v = d;
        if double {
            v *= 2;
            if v >= 32 {
                v -= 32;
            }
        }
        sum += v;
        double = !double;
    }

    sum % 32 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_correct_format() {
        // 用后端同算法生成的卡密
        // 手动构造一个 Luhn mod32 校验通过的卡密
        // 前 15 位固定,计算第 16 位校验位
        let prefix = b"23456789ABCDEFG"; // 15 字符
        let mut sum = 0usize;
        let mut double = true; // 从右数第 1 位(校验位左边)要乘 2
        for &c in prefix.iter().rev() {
            let d = CARD_CHARSET.iter().position(|&x| x == c).unwrap();
            let mut v = d;
            if double {
                v *= 2;
                if v >= 32 {
                    v -= 32;
                }
            }
            sum += v;
            double = !double;
        }
        let check = (32 - (sum % 32)) % 32;
        let check_char = CARD_CHARSET[check] as char;
        let key = format!(
            "{}{}{}{}-{}{}{}{}-{}{}{}{}-{}{}{}{}",
            prefix[0] as char, prefix[1] as char, prefix[2] as char, prefix[3] as char,
            prefix[4] as char, prefix[5] as char, prefix[6] as char, prefix[7] as char,
            prefix[8] as char, prefix[9] as char, prefix[10] as char, prefix[11] as char,
            prefix[12] as char, prefix[13] as char, prefix[14] as char, check_char,
        );
        assert!(validate_card_key(&key));
    }

    #[test]
    fn test_reject_short() {
        assert!(!validate_card_key("ABC-DEF"));
    }

    #[test]
    fn test_reject_invalid_chars() {
        // 含 0/O/1/I
        assert!(!validate_card_key("ABCD-EFGH-IJKL-MNO0"));
        assert!(!validate_card_key("ABCD-EFGH-IJKL-MNOO"));
        assert!(!validate_card_key("ABCD-EFGH-IJKL-MNO1"));
        assert!(!validate_card_key("ABCD-EFGH-IJKL-MNOI"));
    }

    #[test]
    fn test_reject_tampered() {
        // 构造合法卡密后篡改
        let prefix = b"23456789ABCDEFG";
        let mut sum = 0usize;
        let mut double = true;
        for &c in prefix.iter().rev() {
            let d = CARD_CHARSET.iter().position(|&x| x == c).unwrap();
            let mut v = d;
            if double {
                v *= 2;
                if v >= 32 {
                    v -= 32;
                }
            }
            sum += v;
            double = !double;
        }
        let check = (32 - (sum % 32)) % 32;
        let check_char = CARD_CHARSET[check] as char;
        let key = format!(
            "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
            prefix[0] as char, prefix[1] as char, prefix[2] as char, prefix[3] as char,
            prefix[4] as char, prefix[5] as char, prefix[6] as char, prefix[7] as char,
            prefix[8] as char, prefix[9] as char, prefix[10] as char, prefix[11] as char,
            prefix[12] as char, prefix[13] as char, prefix[14] as char, check_char,
        );
        // 篡改第一个字符
        let tampered_first = b"3".to_vec();
        let tampered = format!(
            "{}{}",
            tampered_first[0] as char,
            &key[1..]
        );
        assert!(!validate_card_key(&tampered));
    }
}
