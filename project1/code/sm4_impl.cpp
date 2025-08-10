#include "sm4_shared.h"

// ѭ�����ƺ�
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// --- ��Կ��չ��غ��� ---

// ��Կ��չ�еķ����Ա任 ��
uint32_t tau_key(uint32_t A) {
    uint8_t b[4];
    from_uint32(A, b);
    b[0] = SM4_SBOX[b[0]];
    b[1] = SM4_SBOX[b[1]];
    b[2] = SM4_SBOX[b[2]];
    b[3] = SM4_SBOX[b[3]];
    return to_uint32(b);
}

// ��Կ��չ�е����Ա任 L' 
uint32_t L_prime(uint32_t B) {
    return B ^ ROTL(B, 13) ^ ROTL(B, 23);
}

// SM4 ��Կ��չ���� 
void sm4_set_key(const uint8_t* key, uint32_t* rk) {
    uint32_t K[4];
    K[0] = to_uint32(key);
    K[1] = to_uint32(key + 4);
    K[2] = to_uint32(key + 8);
    K[3] = to_uint32(key + 12);

    K[0] ^= FK[0];
    K[1] ^= FK[1];
    K[2] ^= FK[2];
    K[3] ^= FK[3];

    for (int i = 0; i < SM4_NUM_ROUNDS; ++i) {
        rk[i] = K[0] ^ L_prime(tau_key(K[1] ^ K[2] ^ K[3] ^ CK[i]));
        // ����K������Ϊ��������
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = rk[i];
    }
}


// --- ����ʵ�� ---

// ����/�����е����Ա任 L 
uint32_t L(uint32_t B) {
    return B ^ ROTL(B, 2) ^ ROTL(B, 10) ^ ROTL(B, 18) ^ ROTL(B, 24);
}

// ����/�����еķ����Ա任 ��
uint32_t tau(uint32_t A) {
    uint8_t b[4];
    from_uint32(A, b);
    b[0] = SM4_SBOX[b[0]];
    b[1] = SM4_SBOX[b[1]];
    b[2] = SM4_SBOX[b[2]];
    b[3] = SM4_SBOX[b[3]];
    return to_uint32(b);
}

// ���ϱ任 T 
uint32_t T(uint32_t V) {
    return L(tau(V));
}

// SM4 �������ܺ��� 
void sm4_encrypt_basic(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    uint32_t X[4];
    X[0] = to_uint32(in);
    X[1] = to_uint32(in + 4);
    X[2] = to_uint32(in + 8);
    X[3] = to_uint32(in + 12);

    for (int i = 0; i < SM4_NUM_ROUNDS; ++i) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ rk[i];
        uint32_t X_new = X[0] ^ T(temp);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = X_new;
    }

    // ����任
    from_uint32(X[3], out);
    from_uint32(X[2], out + 4);
    from_uint32(X[1], out + 8);
    from_uint32(X[0], out + 12);
}

// SM4 �������ܺ���
void sm4_decrypt_basic(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    uint32_t X[4];
    X[0] = to_uint32(in);
    X[1] = to_uint32(in + 4);
    X[2] = to_uint32(in + 8);
    X[3] = to_uint32(in + 12);

    // ����ʹ�÷��������Կ
    for (int i = 0; i < SM4_NUM_ROUNDS; ++i) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ rk[31 - i];
        uint32_t X_new = X[0] ^ T(temp);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = X_new;
    }

    // ����任
    from_uint32(X[3], out);
    from_uint32(X[2], out + 4);
    from_uint32(X[1], out + 8);
    from_uint32(X[0], out + 12);
}

// --- T-Table �Ż�ʵ�� ---

static uint32_t T_TABLE[4][256];
static bool t_tables_generated = false;

void generate_ttables() {
    if (t_tables_generated) return;
    for (int i = 0; i < 256; ++i) {
        uint32_t s_val = SM4_SBOX[i];
        T_TABLE[0][i] = L(s_val << 24);
        T_TABLE[1][i] = L(s_val << 16);
        T_TABLE[2][i] = L(s_val << 8);
        T_TABLE[3][i] = L(s_val);
    }
    t_tables_generated = true;
}

// ʹ��T-Table�ĸ��ϱ任 
uint32_t T_ttable(uint32_t V) {
    return T_TABLE[0][(V >> 24) & 0xFF] ^
        T_TABLE[1][(V >> 16) & 0xFF] ^
        T_TABLE[2][(V >> 8) & 0xFF] ^
        T_TABLE[3][(V) & 0xFF];
}

// SM4 T-Table ���ܺ��� 
void sm4_encrypt_ttable(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    if (!t_tables_generated) generate_ttables();

    uint32_t X[4];
    X[0] = to_uint32(in);
    X[1] = to_uint32(in + 4);
    X[2] = to_uint32(in + 8);
    X[3] = to_uint32(in + 12);

    for (int i = 0; i < 32; i++) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ rk[i];
        uint32_t X_new = X[0] ^ T_ttable(temp);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = X_new;
    }

    from_uint32(X[3], out);
    from_uint32(X[2], out + 4);
    from_uint32(X[1], out + 8);
    from_uint32(X[0], out + 12);
}

// SM4 T-Table ���ܺ���
void sm4_decrypt_ttable(const uint8_t* in, uint8_t* out, const uint32_t* rk) {
    if (!t_tables_generated) generate_ttables();

    uint32_t X[4];
    X[0] = to_uint32(in);
    X[1] = to_uint32(in + 4);
    X[2] = to_uint32(in + 8);
    X[3] = to_uint32(in + 12);

    for (int i = 0; i < 32; i++) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ rk[31 - i];
        uint32_t X_new = X[0] ^ T_ttable(temp);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = X_new;
    }

    from_uint32(X[3], out);
    from_uint32(X[2], out + 4);
    from_uint32(X[1], out + 8);
    from_uint32(X[0], out + 12);
}