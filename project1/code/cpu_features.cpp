#include cpu_features.h
#include iostream
#include cstring
#include sstream

#ifdef _MSC_VER
#include intrin.h
#define cpuid(info, x) __cpuidex(info, x, 0)
#else
#include cpuid.h
static void cpuid(int info[4], int InfoType) {
    __cpuid_count(InfoType, 0, info[0], info[1], info[2], info[3]);
}
#endif

 全局CPU特性信息
static cpu_features_t g_cpu_features = { 0 };
static bool g_cpu_features_initialized = false;
static char g_features_string[512] = { 0 };

 内部辅助函数：执行CPUID指令
static void execute_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx) {
    int cpuinfo[4];
#ifdef _MSC_VER
    __cpuidex(cpuinfo, leaf, subleaf);
#else
    __cpuid_count(leaf, subleaf, cpuinfo[0], cpuinfo[1], cpuinfo[2], cpuinfo[3]);
#endif
    eax = cpuinfo[0];
    ebx = cpuinfo[1];
    ecx = cpuinfo[2];
    edx = cpuinfo[3];
}

 检测基本CPU信息
static void detect_cpu_basic_info() {
    uint32_t eax, ebx, ecx, edx;
    
     获取厂商字符串
    execute_cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    memcpy(g_cpu_features.vendor, &ebx, 4);
    memcpy(g_cpu_features.vendor + 4, &edx, 4);
    memcpy(g_cpu_features.vendor + 8, &ecx, 4);
    g_cpu_features.vendor[12] = '0';
    
     获取处理器信息
    execute_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    g_cpu_features.family = ((eax  8) & 0xF) + ((eax  20) & 0xFF);
    g_cpu_features.model = ((eax  4) & 0xF)  ((eax  12) & 0xF0);
    g_cpu_features.stepping = eax & 0xF;
    
     获取品牌字符串
    uint32_t brand[12] = { 0 };
    execute_cpuid(0x80000002, 0, &brand[0], &brand[1], &brand[2], &brand[3]);
    execute_cpuid(0x80000003, 0, &brand[4], &brand[5], &brand[6], &brand[7]);
    execute_cpuid(0x80000004, 0, &brand[8], &brand[9], &brand[10], &brand[11]);
    memcpy(g_cpu_features.brand, brand, 48);
    g_cpu_features.brand[48] = '0';
}

 检测CPU特性支持
static void detect_cpu_features() {
    uint32_t eax, ebx, ecx, edx;
    g_cpu_features.features = 0;
    
     检测基本特性（CPUID leaf 1）
    execute_cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    
     SSE2支持检测
    if (edx & (1  26)) {
        g_cpu_features.features = CPU_FEATURE_SSE2;
    }
    
     SSSE3支持检测
    if (ecx & (1  9)) {
        g_cpu_features.features = CPU_FEATURE_SSSE3;
    }
    
     SSE4.1支持检测
    if (ecx & (1  19)) {
        g_cpu_features.features = CPU_FEATURE_SSE41;
    }
    
     AES-NI支持检测
    if (ecx & (1  25)) {
        g_cpu_features.features = CPU_FEATURE_AES;
    }
    
     PCLMULQDQ支持检测
    if (ecx & (1  1)) {
        g_cpu_features.features = CPU_FEATURE_PCLMULQDQ;
    }
    
     检测扩展特性（CPUID leaf 7）
    execute_cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    
     AVX2支持检测
    if (ebx & (1  5)) {
        g_cpu_features.features = CPU_FEATURE_AVX2;
    }
    
     AVX-512F支持检测
    if (ebx & (1  16)) {
        g_cpu_features.features = CPU_FEATURE_AVX512F;
    }
    
     AVX-512VL支持检测
    if (ebx & (1  31)) {
        g_cpu_features.features = CPU_FEATURE_AVX512VL;
    }
    
     GFNI支持检测
    if (ecx & (1  8)) {
        g_cpu_features.features = CPU_FEATURE_GFNI;
    }
    
     VAES支持检测
    if (ecx & (1  9)) {
        g_cpu_features.features = CPU_FEATURE_VAES;
    }
    
     VPCLMULQDQ支持检测
    if (ecx & (1  10)) {
        g_cpu_features.features = CPU_FEATURE_VPCLMULQDQ;
    }
}

 生成特性字符串
static void generate_features_string() {
    stdostringstream oss;
    
    if (g_cpu_features.features & CPU_FEATURE_SSE2) oss  SSE2 ;
    if (g_cpu_features.features & CPU_FEATURE_SSSE3) oss  SSSE3 ;
    if (g_cpu_features.features & CPU_FEATURE_SSE41) oss  SSE4.1 ;
    if (g_cpu_features.features & CPU_FEATURE_AES) oss  AES-NI ;
    if (g_cpu_features.features & CPU_FEATURE_PCLMULQDQ) oss  PCLMULQDQ ;
    if (g_cpu_features.features & CPU_FEATURE_AVX2) oss  AVX2 ;
    if (g_cpu_features.features & CPU_FEATURE_AVX512F) oss  AVX-512F ;
    if (g_cpu_features.features & CPU_FEATURE_AVX512VL) oss  AVX-512VL ;
    if (g_cpu_features.features & CPU_FEATURE_GFNI) oss  GFNI ;
    if (g_cpu_features.features & CPU_FEATURE_VAES) oss  VAES ;
    if (g_cpu_features.features & CPU_FEATURE_VPCLMULQDQ) oss  VPCLMULQDQ ;
    
    stdstring features_str = oss.str();
    if (!features_str.empty()) {
        features_str.pop_back();  移除最后的空格
    } else {
        features_str = None;
    }
    
    strncpy(g_features_string, features_str.c_str(), sizeof(g_features_string) - 1);
    g_features_string[sizeof(g_features_string) - 1] = '0';
}

 公共接口实现

void cpu_features_init() {
    if (g_cpu_features_initialized) {
        return;
    }
    
    detect_cpu_basic_info();
    detect_cpu_features();
    generate_features_string();
    
    g_cpu_features_initialized = true;
}

const cpu_features_t& get_cpu_features() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return g_cpu_features;
}

bool cpu_supports_aes() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_AES) != 0;
}

bool cpu_supports_gfni() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_GFNI) != 0;
}

bool cpu_supports_avx2() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_AVX2) != 0;
}

bool cpu_supports_avx512() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_AVX512F) != 0;
}

bool cpu_supports_pclmulqdq() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_PCLMULQDQ) != 0;
}

bool cpu_supports_vaes() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_VAES) != 0;
}

bool cpu_supports_vpclmulqdq() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_VPCLMULQDQ) != 0;
}

bool cpu_supports_sse2() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_SSE2) != 0;
}

bool cpu_supports_ssse3() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_SSSE3) != 0;
}

bool cpu_supports_sse41() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return (g_cpu_features.features & CPU_FEATURE_SSE41) != 0;
}

const char get_cpu_features_string() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    return g_features_string;
}

void print_cpu_info() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    
    stdcout  CPU信息  stdendl;
    stdcout    厂商   g_cpu_features.vendor  stdendl;
    stdcout    品牌   g_cpu_features.brand  stdendl;
    stdcout    家族   g_cpu_features.family 
               , 型号   g_cpu_features.model 
               , 步进   g_cpu_features.stepping  stdendl;
    stdcout    支持的指令集   g_features_string  stdendl;
}

const char get_optimal_sm4_implementation() {
    if (!g_cpu_features_initialized) {
        cpu_features_init();
    }
    
     根据CPU特性选择最优实现
    if (cpu_supports_avx512() && cpu_supports_gfni()) {
        return AVX-512 + GFNI;
    } else if (cpu_supports_gfni() && cpu_supports_avx2()) {
        return GFNI + AVX2;
    } else if (cpu_supports_aes() && cpu_supports_avx2()) {
        return AES-NI + AVX2;
    } else if (cpu_supports_aes()) {
        return AES-NI;
    } else if (cpu_supports_ssse3()) {
        return T-Table + SSSE3;
    } else {
        return T-Table;
    }
}