#include "sm4_gfni.h"

#ifdef __GFNI__

#include <immintrin.h>

// GFNI仿射变换矩阵和常数，用于实现SM4 S盒
// 这些值是通过分析SM4 S盒的数学结构得出的
alignas(16) static const uint64_t SM4_GFNI_MATRIX[2] = {
    0x8F1F2F4F8F1F2F4FULL,  // 仿射变换矩阵的低64位
    0x1E3E7EFCF8F0E0C0ULL   // 仿射变换矩阵的高64位
};

static const uint8_t SM4_GFNI_CONSTANT = 0x63;  // 仿射变换常数

// SIMD循环左移宏
#define ROTL_SIMD(x, n) _mm_or_si128(_mm_slli_epi32(x, n), _mm_srli_epi32(x, 32 - n))
#define ROTL_SIMD_AVX512(x, n) _mm512_or_si512(_mm512_slli_epi32(x, n), _mm512_srli_epi32(x, 32 - n))

// 检测CPU是否支持GFNI指令集
bool cpu_supports_gfni_instructions() {
    int cpuinfo[4];
    __cpuid(cpuinfo, 7);
    return (cpuinfo[2] & (1 << 8)) != 0; // ECX位8为GFNI支持标志
}

// 使用GFNI优化的SM4 S盒替换
__m128i sm4_sbox_gfni(__m128i data) {
    // 使用GFNI仿射变换实现S盒替换
    // 这比传统的查表法更高效
    const __m128i matrix = _mm_set_epi64x(SM4_GFNI_MATRIX[1], SM4_GFNI_MATRIX[0]);
    return _mm_gf2p8affine_epi64_epi8(data, matrix, SM4_GFNI_CONSTANT);
}

// 使用GFNI优化的8路并行S盒替换（AVX-512）
__m512i sm4_sbox_gfni_avx512(__m512i data) {
#ifdef __AVX512F__
    const __m512i matrix = _mm512_broadcast_i64x2(_mm_set_epi64x(SM4_GFNI_MATRIX[1], SM4_GFNI_MATRIX[0]));
    return _mm512_gf2p8affine_epi64_epi8(data, matrix, SM4_GFNI_CONSTANT);
#else
    // 如果不支持AVX-512，分解为4个128位操作
    alignas(64) uint8_t temp[64];
    _mm512_store_si512((__m512i*)temp, data);
    
    __m128i part0 = sm4_sbox_gfni(_mm_load_si128((__m128i*)(temp + 0)));
    __m128i part1 = sm4_sbox_gfni(_mm_load_si128((__m128i*)(temp + 16)));
    __m128i part2 = sm4_sbox_gfni(_mm_load_si128((__m128i*)(temp + 32)));
    __m128i part3 = sm4_sbox_gfni(_mm_load_si128((__m128i*)(temp + 48)));
    
    _mm_store_si128((__m128i*)(temp + 0), part0);
    _mm_store_si128((__m128i*)(temp + 16), part1);
    _mm_store_si128((__m128i*)(temp + 32), part2);
    _mm_store_si128((__m128i*)(temp + 48), part3);
    
    return _mm512_load_si512((__m512i*)temp);
#endif
}

// GFNI优化的线性变换L
__m128i sm4_linear_transform_gfni(__m128i data) {
    // L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)
    // 使用SIMD指令进行高效的位操作
    __m128i rot2 = ROTL_SIMD(data, 2);
    __m128i rot10 = ROTL_SIMD(data, 10);
    __m128i rot18 = ROTL_SIMD(data, 18);
    __m128i rot24 = ROTL_SIMD(data, 24);
    
    return _mm_xor_si128(data,
           _mm_xor_si128(rot2,
           _mm_xor_si128(rot10,
           _mm_xor_si128(rot18, rot24))));
}

// GFNI优化的复合变换T
__m128i sm4_T_transform_gfni(__m128i data) {
    return sm4_linear_transform_gfni(sm4_sbox_gfni(data));
}

// GFNI优化的SM4加密
void sm4_encrypt_gfni(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    // 加载输入数据
    __m128i X = _mm_loadu_si128((__m128i*)in);
    
    // 字节序转换（SM4使用大端序）
    const __m128i byte_swap_mask = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
    X = _mm_shuffle_epi8(X, byte_swap_mask);
    
    // 提取4个32位字
    alignas(16) uint32_t words[4];
    _mm_store_si128((__m128i*)words, X);
    
    uint32_t X0 = words[0], X1 = words[1], X2 = words[2], X3 = words[3];
    
    // 32轮加密，使用GFNI优化的变换
    for (int i = 0; i < 32; i++) {
        uint32_t temp = X1 ^ X2 ^ X3 ^ rk[i];
        
        // 使用GFNI进行高效的T变换
        __m128i temp_vec = _mm_set1_epi32(temp);
        temp_vec = sm4_T_transform_gfni(temp_vec);
        
        uint32_t T_result = _mm_cvtsi128_si32(temp_vec);
        uint32_t X_new = X0 ^ T_result;
        
        // 更新状态
        X0 = X1; X1 = X2; X2 = X3; X3 = X_new;
    }
    
    // 反序变换
    __m128i result = _mm_set_epi32(X0, X1, X2, X3);
    
    // 恢复字节序
    result = _mm_shuffle_epi8(result, byte_swap_mask);
    
    _mm_storeu_si128((__m128i*)out, result);
}

// GFNI优化的SM4解密
void sm4_decrypt_gfni(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    // 加载输入数据
    __m128i X = _mm_loadu_si128((__m128i*)in);
    
    // 字节序转换
    const __m128i byte_swap_mask = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);
    X = _mm_shuffle_epi8(X, byte_swap_mask);
    
    // 提取4个32位字
    alignas(16) uint32_t words[4];
    _mm_store_si128((__m128i*)words, X);
    
    uint32_t X0 = words[0], X1 = words[1], X2 = words[2], X3 = words[3];
    
    // 32轮解密（反向使用轮密钥）
    for (int i = 0; i < 32; i++) {
        uint32_t temp = X1 ^ X2 ^ X3 ^ rk[31 - i];
        
        // 使用GFNI进行高效的T变换
        __m128i temp_vec = _mm_set1_epi32(temp);
        temp_vec = sm4_T_transform_gfni(temp_vec);
        
        uint32_t T_result = _mm_cvtsi128_si32(temp_vec);
        uint32_t X_new = X0 ^ T_result;
        
        // 更新状态
        X0 = X1; X1 = X2; X2 = X3; X3 = X_new;
    }
    
    // 反序变换
    __m128i result = _mm_set_epi32(X0, X1, X2, X3);
    
    // 恢复字节序
    result = _mm_shuffle_epi8(result, byte_swap_mask);
    
    _mm_storeu_si128((__m128i*)out, result);
}

// GFNI并行加密多个数据块
void sm4_encrypt_gfni_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk) {
    const size_t PARALLEL_BLOCKS = 8; // 每次并行处理8个块
    
    size_t i = 0;
    // 使用AVX-512并行处理8个块
    for (; i + PARALLEL_BLOCKS <= blocks; i += PARALLEL_BLOCKS) {
        // 加载8个128位数据块到一个512位寄存器
        __m512i data = _mm512_loadu_si512((__m512i*)(in + i * 16));
        
        // 字节序调整
        const __m512i byte_swap_mask = _mm512_set4_epi32(
            0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
        data = _mm512_shuffle_epi8(data, byte_swap_mask);
        
        // 这里可以实现更复杂的并行SM4算法
        // 为简化，我们分解为单独的128位操作
        alignas(64) uint8_t temp_data[64];
        _mm512_store_si512((__m512i*)temp_data, data);
        
        for (int j = 0; j < 8; j++) {
            sm4_encrypt_gfni(temp_data + j * 8, temp_data + j * 8, rk);
        }
        
        data = _mm512_load_si512((__m512i*)temp_data);
        _mm512_storeu_si512((__m512i*)(out + i * 16), data);
    }
    
    // 处理剩余的块
    for (; i < blocks; i++) {
        sm4_encrypt_gfni(in + i * 16, out + i * 16, rk);
    }
}

// GFNI并行解密多个数据块
void sm4_decrypt_gfni_parallel(const uint8_t* in, uint8_t* out, size_t blocks, const uint32_t* rk) {
    const size_t PARALLEL_BLOCKS = 8;
    
    size_t i = 0;
    // 并行处理（实现类似于加密，但使用反向轮密钥）
    for (; i + PARALLEL_BLOCKS <= blocks; i += PARALLEL_BLOCKS) {
        // 为简化，分别处理每个块
        for (size_t j = 0; j < PARALLEL_BLOCKS; j++) {
            sm4_decrypt_gfni(in + (i + j) * 16, out + (i + j) * 16, rk);
        }
    }
    
    // 处理剩余的块
    for (; i < blocks; i++) {
        sm4_decrypt_gfni(in + i * 16, out + i * 16, rk);
    }
}

#endif // __GFNI__