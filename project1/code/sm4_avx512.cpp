#include "sm4_avx512.h"

#ifdef __AVX512F__

#include <immintrin.h>

// AVX-512对齐的S盒查找表
alignas(64) static const uint8_t SM4_SBOX_AVX512[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// 检测CPU是否支持AVX-512指令集
bool cpu_supports_avx512_instructions() {
    int cpuinfo[4];
    __cpuid(cpuinfo, 7);
    return (cpuinfo[1] & (1 << 16)) != 0; // EBX位16为AVX-512F支持标志
}

// 检测CPU是否支持VPROLD指令
bool cpu_supports_vprold() {
    int cpuinfo[4];
    __cpuid(cpuinfo, 7);
    return (cpuinfo[1] & (1 << 16)) != 0; // VPROLD是AVX-512F的一部分
}

// 使用VPROLD指令优化的循环左移
__m512i sm4_vprold_rotate(__m512i data, int rotation) {
#ifdef __AVX512VBMI__
    return _mm512_rol_epi32(data, rotation);
#else
    // 如果不支持VPROLD，使用传统方法
    return _mm512_or_si512(
        _mm512_slli_epi32(data, rotation),
        _mm512_srli_epi32(data, 32 - rotation)
    );
#endif
}

// AVX-512优化的S盒替换（16路并行）
__m512i sm4_sbox_avx512(__m512i data) {
    // 将512位数据分解为64个字节，进行S盒查找
    alignas(64) uint8_t bytes[64];
    _mm512_store_si512((__m512i*)bytes, data);
    
    // 并行S盒查找
    for (int i = 0; i < 64; i++) {
        bytes[i] = SM4_SBOX_AVX512[bytes[i]];
    }
    
    return _mm512_load_si512((__m512i*)bytes);
}

// AVX-512优化的线性变换L（16路并行）
__m512i sm4_linear_transform_avx512(__m512i data) {
    // L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)
    // 使用VPROLD指令进行高效的循环左移
    __m512i rot2 = sm4_vprold_rotate(data, 2);
    __m512i rot10 = sm4_vprold_rotate(data, 10);
    __m512i rot18 = sm4_vprold_rotate(data, 18);
    __m512i rot24 = sm4_vprold_rotate(data, 24);
    
    return _mm512_xor_si512(data,
           _mm512_xor_si512(rot2,
           _mm512_xor_si512(rot10,
           _mm512_xor_si512(rot18, rot24))));
}

// AVX-512优化的复合变换T（16路并行）
__m512i sm4_T_transform_avx512(__m512i data) {
    return sm4_linear_transform_avx512(sm4_sbox_avx512(data));
}

// AVX-512优化的SM4加密（单块）
void sm4_encrypt_avx512(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    // 对于单块，使用较简单的实现
    // 实际项目中可以进一步优化
    __m128i X = _mm_loadu_si128((__m128i*)in);
    
    // 字节序转换
    const __m128i byte_swap_mask = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
    X = _mm_shuffle_epi8(X, byte_swap_mask);
    
    // 扩展到512位进行处理
    __m512i X_512 = _mm512_broadcast_i32x4(X);
    
    // 提取4个32位字
    alignas(16) uint32_t words[4];
    _mm_store_si128((__m128i*)words, X);
    
    uint32_t X0 = words[0], X1 = words[1], X2 = words[2], X3 = words[3];
    
    // 32轮加密
    for (int i = 0; i < 32; i++) {
        uint32_t temp = X1 ^ X2 ^ X3 ^ rk[i];
        
        // 使用AVX-512进行T变换
        __m512i temp_512 = _mm512_set1_epi32(temp);
        temp_512 = sm4_T_transform_avx512(temp_512);
        
        uint32_t T_result = _mm512_cvtsi512_si32(temp_512);
        uint32_t X_new = X0 ^ T_result;
        
        // 更新状态
        X0 = X1; X1 = X2; X2 = X3; X3 = X_new;
    }
    
    // 反序变换
    __m128i result = _mm_set_epi32(X0, X1, X2, X3);
    result = _mm_shuffle_epi8(result, byte_swap_mask);
    
    _mm_storeu_si128((__m128i*)out, result);
}

// AVX-512优化的SM4解密（单块）
void sm4_decrypt_avx512(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    // 实现与加密类似，但轮密钥顺序相反
    __m128i X = _mm_loadu_si128((__m128i*)in);
    
    const __m128i byte_swap_mask = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
    X = _mm_shuffle_epi8(X, byte_swap_mask);
    
    alignas(16) uint32_t words[4];
    _mm_store_si128((__m128i*)words, X);
    
    uint32_t X0 = words[0], X1 = words[1], X2 = words[2], X3 = words[3];
    
    // 32轮解密（反向轮密钥）
    for (int i = 0; i < 32; i++) {
        uint32_t temp = X1 ^ X2 ^ X3 ^ rk[31 - i];
        
        __m512i temp_512 = _mm512_set1_epi32(temp);
        temp_512 = sm4_T_transform_avx512(temp_512);
        
        uint32_t T_result = _mm512_cvtsi512_si32(temp_512);
        uint32_t X_new = X0 ^ T_result;
        
        X0 = X1; X1 = X2; X2 = X3; X3 = X_new;
    }
    
    __m128i result = _mm_set_epi32(X0, X1, X2, X3);
    result = _mm_shuffle_epi8(result, byte_swap_mask);
    
    _mm_storeu_si128((__m128i*)out, result);
}

// AVX-512并行处理16个数据块
void sm4_encrypt_avx512_16blocks(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    // 加载16个128位数据块到四个512位寄存器
    __m512i block0 = _mm512_loadu_si512((__m512i*)(in + 0 * 64));
    __m512i block1 = _mm512_loadu_si512((__m512i*)(in + 1 * 64));
    __m512i block2 = _mm512_loadu_si512((__m512i*)(in + 2 * 64));
    __m512i block3 = _mm512_loadu_si512((__m512i*)(in + 3 * 64));
    
    // 字节序调整
    const __m512i byte_swap_mask = _mm512_set4_epi32(
        0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
    
    block0 = _mm512_shuffle_epi8(block0, byte_swap_mask);
    block1 = _mm512_shuffle_epi8(block1, byte_swap_mask);
    block2 = _mm512_shuffle_epi8(block2, byte_swap_mask);
    block3 = _mm512_shuffle_epi8(block3, byte_swap_mask);
    
    // 这里可以实现更复杂的16路并行SM4算法
    // 为简化实现，我们分别处理每4个块
    alignas(64) uint8_t temp0[64], temp1[64], temp2[64], temp3[64];
    
    _mm512_store_si512((__m512i*)temp0, block0);
    _mm512_store_si512((__m512i*)temp1, block1);
    _mm512_store_si512((__m512i*)temp2, block2);
    _mm512_store_si512((__m512i*)temp3, block3);
    
    // 并行处理4个块组
    for (int i = 0; i < 4; i++) {
        sm4_encrypt_avx512(temp0 + i * 16, temp0 + i * 16, rk);
        sm4_encrypt_avx512(temp1 + i * 16, temp1 + i * 16, rk);
        sm4_encrypt_avx512(temp2 + i * 16, temp2 + i * 16, rk);
        sm4_encrypt_avx512(temp3 + i * 16, temp3 + i * 16, rk);
    }
    
    // 恢复并输出
    block0 = _mm512_load_si512((__m512i*)temp0);
    block1 = _mm512_load_si512((__m512i*)temp1);
    block2 = _mm512_load_si512((__m512i*)temp2);
    block3 = _mm512_load_si512((__m512i*)temp3);
    
    block0 = _mm512_shuffle_epi8(block0, byte_swap_mask);
    block1 = _mm512_shuffle_epi8(block1, byte_swap_mask);
    block2 = _mm512_shuffle_epi8(block2, byte_swap_mask);
    block3 = _mm512_shuffle_epi8(block3, byte_swap_mask);
    
    _mm512_storeu_si512((__m512i*)(out + 0 * 64), block0);
    _mm512_storeu_si512((__m512i*)(out + 1 * 64), block1);
    _mm512_storeu_si512((__m512i*)(out + 2 * 64), block2);
    _mm512_storeu_si512((__m512i*)(out + 3 * 64), block3);
}

// AVX-512并行解密16个数据块
void sm4_decrypt_avx512_16blocks(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    // 实现类似于加密，但使用解密函数
    for (int i = 0; i < 16; i++) {
        sm4_decrypt_avx512(in + i * 16, out + i * 16, rk);
    }
}

// AVX-512批量处理
void sm4_encrypt_avx512_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk) {
    const size_t PARALLEL_BLOCKS = 16; // 每次处理16个块
    
    size_t i = 0;
    // 批量处理16个块
    for (; i + PARALLEL_BLOCKS <= blocks; i += PARALLEL_BLOCKS) {
        sm4_encrypt_avx512_16blocks(in + i * 16, out + i * 16, rk);
    }
    
    // 处理剩余的块
    for (; i < blocks; i++) {
        sm4_encrypt_avx512(in + i * 16, out + i * 16, rk);
    }
}

// AVX-512批量解密
void sm4_decrypt_avx512_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk) {
    const size_t PARALLEL_BLOCKS = 16;
    
    size_t i = 0;
    for (; i + PARALLEL_BLOCKS <= blocks; i += PARALLEL_BLOCKS) {
        sm4_decrypt_avx512_16blocks(in + i * 16, out + i * 16, rk);
    }
    
    for (; i < blocks; i++) {
        sm4_decrypt_avx512(in + i * 16, out + i * 16, rk);
    }
}

#endif // __AVX512F__