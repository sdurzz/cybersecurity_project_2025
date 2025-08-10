#pragma once
#include "sm4_shared.h"

#ifdef __GFNI__
#include <immintrin.h>

/**
 * 使用GFNI指令集优化的SM4加密函数
 * GFNI指令特别适合优化密码学中的S盒替换操作
 * @param in 输入明文块（16字节）
 * @param out 输出密文块（16字节）
 * @param rk 轮密钥数组
 */
void sm4_encrypt_gfni(const uint8_t* in, uint8_t* out, const uint32_t* rk);

/**
 * 使用GFNI指令集优化的SM4解密函数
 * @param in 输入密文块（16字节）
 * @param out 输出明文块（16字节）
 * @param rk 轮密钥数组
 */
void sm4_decrypt_gfni(const uint8_t* in, uint8_t* out, const uint32_t* rk);

/**
 * GFNI并行处理多个数据块
 * @param in 输入数据块数组
 * @param out 输出数据块数组
 * @param blocks 数据块数量
 * @param rk 轮密钥数组
 */
void sm4_encrypt_gfni_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk);

/**
 * GFNI并行解密多个数据块
 * @param in 输入数据块数组
 * @param out 输出数据块数组
 * @param blocks 数据块数量
 * @param rk 轮密钥数组
 */
void sm4_decrypt_gfni_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk);

/**
 * 使用GFNI优化的SM4 S盒替换
 * GFNI的仿射变换指令可以高效实现S盒操作
 * @param data 128位输入数据
 * @return 经过S盒替换的128位数据
 */
__m128i sm4_sbox_gfni(__m128i data);

/**
 * 使用GFNI优化的8个并行S盒替换
 * @param data 512位输入数据（8个并行字节）
 * @return 经过S盒替换的512位数据
 */
__m512i sm4_sbox_gfni_avx512(__m512i data);

/**
 * GFNI优化的线性变换L
 * @param data 128位输入数据
 * @return 经过线性变换的128位数据
 */
__m128i sm4_linear_transform_gfni(__m128i data);

/**
 * GFNI优化的复合变换T（S盒+线性变换）
 * @param data 128位输入数据
 * @return 经过复合变换的128位数据
 */
__m128i sm4_T_transform_gfni(__m128i data);

/**
 * 检测CPU是否支持GFNI指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_gfni_instructions();

#else
// 如果编译器不支持GFNI，提供回退实现
inline void sm4_encrypt_gfni(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    sm4_encrypt_aesni(in, out, rk);
}

inline void sm4_decrypt_gfni(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    sm4_decrypt_aesni(in, out, rk);
}

inline bool cpu_supports_gfni_instructions() {
    return false;
}

#endif // __GFNI__