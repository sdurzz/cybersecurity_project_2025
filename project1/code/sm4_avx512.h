#pragma once
#include "sm4_shared.h"

#ifdef __AVX512F__
#include <immintrin.h>

/**
 * 使用AVX-512指令集优化的SM4加密函数
 * 利用512位向量寄存器实现高度并行化
 * @param in 输入明文块（16字节）
 * @param out 输出密文块（16字节）
 * @param rk 轮密钥数组
 */
void sm4_encrypt_avx512(const uint8_t* in, uint8_t* out, const uint32_t* rk);

/**
 * 使用AVX-512指令集优化的SM4解密函数
 * @param in 输入密文块（16字节）
 * @param out 输出明文块（16字节）
 * @param rk 轮密钥数组
 */
void sm4_decrypt_avx512(const uint8_t* in, uint8_t* out, const uint32_t* rk);

/**
 * AVX-512并行处理16个数据块
 * 这是AVX-512的主要优势：512位寄存器可以同时处理更多数据
 * @param in 输入数据块数组
 * @param out 输出数据块数组
 * @param rk 轮密钥数组
 */
void sm4_encrypt_avx512_16blocks(const uint8_t* in, uint8_t* out, const uint32_t* rk);

/**
 * AVX-512并行解密16个数据块
 * @param in 输入数据块数组
 * @param out 输出数据块数组
 * @param rk 轮密钥数组
 */
void sm4_decrypt_avx512_16blocks(const uint8_t* in, uint8_t* out, const uint32_t* rk);

/**
 * AVX-512批量处理（适用于大数据）
 * @param in 输入数据块数组
 * @param out 输出数据块数组
 * @param blocks 数据块数量
 * @param rk 轮密钥数组
 */
void sm4_encrypt_avx512_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk);

/**
 * AVX-512批量解密
 * @param in 输入数据块数组
 * @param out 输出数据块数组
 * @param blocks 数据块数量
 * @param rk 轮密钥数组
 */
void sm4_decrypt_avx512_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk);

/**
 * 使用VPROLD指令优化的循环左移
 * VPROLD是AVX-512中新增的向量循环左移指令
 * @param data 512位输入数据
 * @param rotation 左移位数
 * @return 循环左移后的512位数据
 */
__m512i sm4_vprold_rotate(__m512i data, int rotation);

/**
 * AVX-512优化的S盒替换（16路并行）
 * @param data 512位输入数据（16个32位字）
 * @return 经过S盒替换的512位数据
 */
__m512i sm4_sbox_avx512(__m512i data);

/**
 * AVX-512优化的线性变换L（16路并行）
 * @param data 512位输入数据
 * @return 经过线性变换的512位数据
 */
__m512i sm4_linear_transform_avx512(__m512i data);

/**
 * AVX-512优化的复合变换T（16路并行）
 * @param data 512位输入数据
 * @return 经过复合变换的512位数据
 */
__m512i sm4_T_transform_avx512(__m512i data);

/**
 * 检测CPU是否支持AVX-512指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_avx512_instructions();

/**
 * 检测CPU是否支持VPROLD指令
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_vprold();

#else
// 如果编译器不支持AVX-512，提供回退实现
inline void sm4_encrypt_avx512(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    sm4_encrypt_gfni(in, out, rk);
}

inline void sm4_decrypt_avx512(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    sm4_decrypt_gfni(in, out, rk);
}

inline bool cpu_supports_avx512_instructions() {
    return false;
}

inline bool cpu_supports_vprold() {
    return false;
}

#endif // __AVX512F__