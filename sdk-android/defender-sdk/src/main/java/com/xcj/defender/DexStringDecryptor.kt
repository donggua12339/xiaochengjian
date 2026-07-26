package com.xcj.defender

/**
 * T4 DEX 字符串解密器(运行时,ADR 0090)。
 *
 * 构建期 DexStringEncryptor 将用户 DEX 中的 const-string 替换为:
 *   invoke-static {index}, DexStringDecryptor.get(I)
 *
 * 本类在运行时被调用:从 XcjEncStringTable.DATA[index] 取加密 byte[],
 * 调 native XOR 解密,返回明文 String。
 *
 * 密钥在 native 层(t4_str_key.h),受 X0 SO 加密保护。
 */
object DexStringDecryptor {

    /**
     * 按索引解密字符串。
     * @param index 构建期分配的字符串索引
     * @return 解密后的明文 String
     */
    @JvmStatic
    external fun get(index: Int): String
}
