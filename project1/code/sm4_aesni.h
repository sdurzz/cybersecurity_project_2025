#pragma once
#include "sm4_shared.h"

#ifdef __AES__
#include <immintrin.h>
#include <wmmintrin.h>

/**
 * 使用AES-NI指令集优化的SM4加密函数
 * @param in 输入明文块（16字节）
 * @param out 输出密文块（16字节）
 * @param rk 轮密钥数组
 */
void sm4_encrypt_aesni(const uint8_t* in, uint8_t* out, const uint32_t* rk);

/**
 * 使用AES-NI指令集优化的SM4解密函数
 * @param in 输入密文块（16字节）
 * @param out 输出明文块（16字节）
 * @param rk 轮密钥数组
 */
void sm4_decrypt_aesni(const uint8_t* in, uint8_t* out, const uint32_t* rk);

/**
 * AES-NI并行处理多个数据块
 * @param in 输入数据块数组
 * @param out 输出数据块数组
 * @param blocks 数据块数量
 * @param rk 轮密钥数组
 */
void sm4_encrypt_aesni_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk);

/**
 * AES-NI并行解密多个数据块
 * @param in 输入数据块数组
 * @param out 输出数据块数组
 * @param blocks 数据块数量
 * @param rk 轮密钥数组
 */
void sm4_decrypt_aesni_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk);

/**
 * 使用AES-NI优化的密钥扩展
 * @param key 128位密钥
 * @param rk 输出轮密钥数组
 */
void sm4_set_key_aesni(const uint8_t* key, uint32_t* rk);

/**
 * AES-NI优化的S盒替换
 * @param data 128位数据
 * @return 替换后的128位数据
 */
__m128i sm4_sbox_aesni(__m128i data);

/**
 * AES-NI优化的线性变换
 * @param data 128位数据
 * @return 变换后的128位数据
 */
__m128i sm4_linear_transform_aesni(__m128i data);

/**
 * 检测CPU是否支持AES-NI指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_aesni();

#else
// 如果编译器不支持AES-NI，提供空实现
inline void sm4_encrypt_aesni(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    sm4_encrypt_ttable(in, out, rk);
}

inline void sm4_decrypt_aesni(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    sm4_decrypt_ttable(in, out, rk);
}

inline bool cpu_supports_aesni() {
    return false;
}

#endif // __AES__