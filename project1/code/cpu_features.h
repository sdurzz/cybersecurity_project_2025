#pragma once
#include <cstdint>

/**
 * CPU特性检测工具
 * 用于在运行时检测CPU支持的指令集扩展
 */

// CPU特性位标志
constexpr uint32_t CPU_FEATURE_AES     = 1 << 0;  // AES-NI指令集
constexpr uint32_t CPU_FEATURE_GFNI    = 1 << 1;  // GFNI指令集
constexpr uint32_t CPU_FEATURE_AVX2    = 1 << 2;  // AVX2指令集
constexpr uint32_t CPU_FEATURE_AVX512F = 1 << 3;  // AVX-512 Foundation
constexpr uint32_t CPU_FEATURE_AVX512VL= 1 << 4;  // AVX-512 Vector Length
constexpr uint32_t CPU_FEATURE_VAES    = 1 << 5;  // Vector AES
constexpr uint32_t CPU_FEATURE_VPCLMULQDQ = 1 << 6; // Vector PCLMULQDQ
constexpr uint32_t CPU_FEATURE_SSE2    = 1 << 7;  // SSE2指令集
constexpr uint32_t CPU_FEATURE_SSSE3   = 1 << 8;  // SSSE3指令集
constexpr uint32_t CPU_FEATURE_SSE41   = 1 << 9;  // SSE4.1指令集
constexpr uint32_t CPU_FEATURE_PCLMULQDQ = 1 << 10; // PCLMULQDQ指令

/**
 * CPU特性信息结构体
 */
struct cpu_features_t {
    uint32_t features;          // 特性位标志
    char vendor[13];            // CPU厂商字符串
    char brand[49];             // CPU品牌字符串
    int family;                 // CPU家族
    int model;                  // CPU型号
    int stepping;               // CPU步进
};

/**
 * 初始化CPU特性检测
 * 必须在使用其他函数前调用
 */
void cpu_features_init();

/**
 * 获取CPU特性信息
 * @return CPU特性结构体
 */
const cpu_features_t& get_cpu_features();

/**
 * 检测CPU是否支持AES-NI指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_aes();

/**
 * 检测CPU是否支持GFNI指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_gfni();

/**
 * 检测CPU是否支持AVX2指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_avx2();

/**
 * 检测CPU是否支持AVX-512指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_avx512();

/**
 * 检测CPU是否支持PCLMULQDQ指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_pclmulqdq();

/**
 * 检测CPU是否支持Vector AES指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_vaes();

/**
 * 检测CPU是否支持Vector PCLMULQDQ指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_vpclmulqdq();

/**
 * 检测CPU是否支持SSE2指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_sse2();

/**
 * 检测CPU是否支持SSSE3指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_ssse3();

/**
 * 检测CPU是否支持SSE4.1指令集
 * @return true表示支持，false表示不支持
 */
bool cpu_supports_sse41();

/**
 * 获取CPU特性的字符串描述
 * @return 包含所有支持特性的字符串
 */
const char* get_cpu_features_string();

/**
 * 打印CPU信息和支持的特性
 */
void print_cpu_info();

/**
 * 根据CPU特性选择最优的SM4实现
 * @return 推荐的实现类型字符串
 */
const char* get_optimal_sm4_implementation();