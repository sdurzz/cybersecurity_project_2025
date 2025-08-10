#include "sm4_gcm.h"
#include <cstring>
#include <algorithm>

// GCMʹ��٤������GF(2^128)�ϵ�����
// ����Լ����ʽΪx^128 + x^7 + x^2 + x + 1

// Ԥ�����GF(2^128)�˷���
uint64_t H_TABLE[16][256] = { {0} };
bool h_tables_initialized = false;

// ������������128λ����ת��Ϊ����64λ�������Ա���и�Ч����
void block_to_words(const uint8_t* block, uint64_t& high, uint64_t& low) {
    high = 0;
    low = 0;
    for (int i = 0; i < 8; i++) {
        high = (high << 8) | block[i];
        low = (low << 8) | block[i + 8];
    }
}

// ����������������64λ����ת����128λ���ݿ�
void words_to_block(uint64_t high, uint64_t low, uint8_t* block) {
    for (int i = 7; i >= 0; i--) {
        block[i] = high & 0xFF;
        high >>= 8;
        block[i + 8] = low & 0xFF;
        low >>= 8;
    }
}

// GF(2^128)�ϵĻ����˷�ʵ��
void gf_multiply_basic(const uint8_t* X, const uint8_t* Y, uint8_t* out) {
    uint8_t Z[16] = { 0 };
    uint8_t V[16];
    memcpy(V, Y, 16);

    // ʵ��"�޽�λ"�˷�
    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            if (X[i] & (1 << j)) {
                // ��V���Z��
                for (int k = 0; k < 16; k++) {
                    Z[k] ^= V[k];
                }
            }

            // ��V����1λ
            bool carry = false;
            for (int k = 15; k >= 0; k--) {
                bool next_carry = V[k] & 0x80;
                V[k] = (V[k] << 1) | (carry ? 1 : 0);
                carry = next_carry;
            }

            // ����н�λ����Լ������ʽ���
            if (carry) {
                V[15] ^= 0xE1; // ����Լ����ʽ�ĵ�λ��0xE1 = 11100001��
            }
        }
    }

    memcpy(out, Z, 16);
}

// ��ʼ�������Ż�GF(2^128)�˷���Ԥ�����
void init_gf_tables(const uint8_t* H) {
    // ������������Ż�GF(2^128)�˷�
    uint8_t Z[16] = { 0 };
    uint8_t tmp[16];

    // ��ʼ���ֽ�0�������Ч�ֽڣ��ı�
    for (int i = 0; i < 256; i++) {
        memset(Z, 0, 16);
        Z[0] = i;
        gf_multiply_basic(Z, H, tmp);
        block_to_words(tmp, H_TABLE[0][i], H_TABLE[8][i]);
    }

    // ʹ�õ�һ����������������
    for (int i = 1; i < 8; i++) {
        for (int j = 0; j < 256; j++) {
            H_TABLE[i][j] = H_TABLE[i - 1][j] >> 8;
            H_TABLE[i][j] |= H_TABLE[i + 7][j] << 56;
            H_TABLE[i + 8][j] = H_TABLE[i + 7][j] >> 8;
        }
    }

    h_tables_initialized = true;
}

// ʹ��Ԥ������Ż���GF(2^128)�˷�
void gf_multiply(const uint8_t* X, const uint8_t* Y, uint8_t* out) {
    if (!h_tables_initialized) {
        // ������δ��ʼ������ʹ�û���ʵ��
        gf_multiply_basic(X, Y, out);
        return;
    }

    // ʹ�ñ���Ż��ĳ˷�ʵ��
    uint64_t Z_high = 0;
    uint64_t Z_low = 0;

    for (int i = 0; i < 16; i++) {
        Z_high ^= H_TABLE[i][X[i]];
        Z_low ^= H_TABLE[i + 8][X[i]];
    }

    words_to_block(Z_high, Z_low, out);
}

// GCM��֤�е�GHASH����
void ghash(const uint8_t* H, const uint8_t* A, size_t A_len, const uint8_t* C, size_t C_len, uint8_t* out) {
    uint8_t X[16] = { 0 }; // �ۼ���
    uint8_t tmp[16];
    size_t remaining;

    // ����AAD���ݿ�
    remaining = A_len;
    while (remaining >= 16) {
        for (int i = 0; i < 16; i++) {
            X[i] ^= A[i];
        }
        gf_multiply(X, H, X);
        A += 16;
        remaining -= 16;
    }

    // ����ʣ���AAD�ֽ�
    if (remaining > 0) {
        memset(tmp, 0, 16);
        memcpy(tmp, A, remaining);
        for (int i = 0; i < 16; i++) {
            X[i] ^= tmp[i];
        }
        gf_multiply(X, H, X);
    }

    // �����������ݿ�
    remaining = C_len;
    while (remaining >= 16) {
        for (int i = 0; i < 16; i++) {
            X[i] ^= C[i];
        }
        gf_multiply(X, H, X);
        C += 16;
        remaining -= 16;
    }

    // ����ʣ��������ֽ�
    if (remaining > 0) {
        memset(tmp, 0, 16);
        memcpy(tmp, C, remaining);
        for (int i = 0; i < 16; i++) {
            X[i] ^= tmp[i];
        }
        gf_multiply(X, H, X);
    }

    // ����A��C�ĳ��ȣ���λΪ��λ��
    uint64_t a_len_bits = A_len * 8;
    uint64_t c_len_bits = C_len * 8;

    memset(tmp, 0, 16);
    // �Դ�˸�ʽ�洢����
    tmp[0] = (a_len_bits >> 56) & 0xFF;
    tmp[1] = (a_len_bits >> 48) & 0xFF;
    tmp[2] = (a_len_bits >> 40) & 0xFF;
    tmp[3] = (a_len_bits >> 32) & 0xFF;
    tmp[4] = (a_len_bits >> 24) & 0xFF;
    tmp[5] = (a_len_bits >> 16) & 0xFF;
    tmp[6] = (a_len_bits >> 8) & 0xFF;
    tmp[7] = a_len_bits & 0xFF;

    tmp[8] = (c_len_bits >> 56) & 0xFF;
    tmp[9] = (c_len_bits >> 48) & 0xFF;
    tmp[10] = (c_len_bits >> 40) & 0xFF;
    tmp[11] = (c_len_bits >> 32) & 0xFF;
    tmp[12] = (c_len_bits >> 24) & 0xFF;
    tmp[13] = (c_len_bits >> 16) & 0xFF;
    tmp[14] = (c_len_bits >> 8) & 0xFF;
    tmp[15] = c_len_bits & 0xFF;

    for (int i = 0; i < 16; i++) {
        X[i] ^= tmp[i];
    }
    gf_multiply(X, H, X);

    memcpy(out, X, 16);
}

// ��������������������ĺ�4���ֽڣ�
void increment_counter(uint8_t* counter) {
    uint32_t ctr = (counter[12] << 24) | (counter[13] << 16) | (counter[14] << 8) | counter[15];
    ctr++;
    counter[12] = (ctr >> 24) & 0xFF;
    counter[13] = (ctr >> 16) & 0xFF;
    counter[14] = (ctr >> 8) & 0xFF;
    counter[15] = ctr & 0xFF;
}

// ���ɳ�ʼ��������J0
void generate_J0(const uint8_t* iv, size_t iv_len, const uint8_t* H, uint8_t* J0) {
    if (iv_len == 12) {  // 96λIV���Ƽ���
        memcpy(J0, iv, 12);
        J0[12] = 0;
        J0[13] = 0;
        J0[14] = 0;
        J0[15] = 1;
    }
    else {
        // IV����96λ - ʹ��GHASH
        uint8_t tmp[16] = { 0 };
        ghash(H, nullptr, 0, iv, iv_len, J0);

        // ����IV�ĳ��ȣ���λΪ��λ��
        uint64_t iv_len_bits = iv_len * 8;
        memset(tmp, 0, 16);
        tmp[8] = (iv_len_bits >> 56) & 0xFF;
        tmp[9] = (iv_len_bits >> 48) & 0xFF;
        tmp[10] = (iv_len_bits >> 40) & 0xFF;
        tmp[11] = (iv_len_bits >> 32) & 0xFF;
        tmp[12] = (iv_len_bits >> 24) & 0xFF;
        tmp[13] = (iv_len_bits >> 16) & 0xFF;
        tmp[14] = (iv_len_bits >> 8) & 0xFF;
        tmp[15] = iv_len_bits & 0xFF;

        for (int i = 0; i < 16; i++) {
            J0[i] ^= tmp[i];
        }
        gf_multiply(J0, H, J0);
    }
}

// ������֤��ǩ
void generate_tag(const uint8_t* J0, const uint8_t* S, const uint32_t* round_keys, uint8_t* tag) {
    uint8_t mask[16];
    sm4_encrypt_ttable(J0, mask, round_keys); // ����J0

    // ��GHASH������õ���ǩ
    for (int i = 0; i < 16; i++) {
        tag[i] = mask[i] ^ S[i];
    }
}

// ��ʼ��GCMģʽ��Ԥ������
void sm4_gcm_init(const uint8_t* key, uint8_t* H_out) {
    // ���ɹ�ϣ����ԿH = E_K(0^128)
    uint8_t H[16] = { 0 };
    uint32_t round_keys[SM4_NUM_ROUNDS];

    sm4_set_key(key, round_keys);
    sm4_encrypt_ttable(H, H, round_keys);

    // ��ʼ��GF(2^128)�˷��Ŀ��ٱ��
    init_gf_tables(H);

    // �����Ҫ������H
    if (H_out) {
        memcpy(H_out, H, 16);
    }
}

// SM4-GCM����
bool sm4_gcm_encrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t* tag
) {
    if (!key || !iv || !tag || (plaintext_len > 0 && (!plaintext || !ciphertext)))
        return false;

    uint32_t round_keys[SM4_NUM_ROUNDS];
    uint8_t H[16] = { 0 };
    uint8_t J0[16];
    uint8_t S[16] = { 0 };
    uint8_t counter[16];
    uint8_t block[16];
    size_t remaining;

    // ��ʼ����Կ
    sm4_set_key(key, round_keys);

    // ���ɹ�ϣ����ԿH = E_K(0^128)
    sm4_encrypt_ttable(H, H, round_keys);

    // �����δ��ʼ���������г�ʼ��
    if (!h_tables_initialized) {
        init_gf_tables(H);
    }

    // ���ɳ�ʼ��������J0
    generate_J0(iv, iv_len, H, J0);

    // ���������õļ���������J0+1��ʼ
    memcpy(counter, J0, 16);
    increment_counter(counter);

    // ��������
    remaining = plaintext_len;
    size_t total_blocks = (plaintext_len + 15) / 16;

    // ���������Ŀ�
    for (size_t i = 0; i < total_blocks; i++) {
        size_t block_size = (i == total_blocks - 1 && remaining < 16) ? remaining : 16;

        // ���ܼ�����
        sm4_encrypt_ttable(counter, block, round_keys);

        // ���������õ�����
        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ block[j];
        }

        // ����������
        increment_counter(counter);
        remaining -= block_size;
    }

    // ������֤��ǩ
    ghash(H, aad, aad_len, ciphertext, plaintext_len, S);
    generate_tag(J0, S, round_keys, tag);

    return true;
}

// SM4-GCM���ܺ���֤
bool sm4_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    uint8_t* plaintext,
    const uint8_t* tag
) {
    if (!key || !iv || !tag || (ciphertext_len > 0 && (!ciphertext || !plaintext)))
        return false;

    uint32_t round_keys[SM4_NUM_ROUNDS];
    uint8_t H[16] = { 0 };
    uint8_t J0[16];
    uint8_t S[16] = { 0 };
    uint8_t calculated_tag[16];
    uint8_t counter[16];
    uint8_t block[16];
    size_t remaining;

    // ��ʼ����Կ
    sm4_set_key(key, round_keys);

    // ���ɹ�ϣ����ԿH = E_K(0^128)
    sm4_encrypt_ttable(H, H, round_keys);

    // �����δ��ʼ���������г�ʼ��
    if (!h_tables_initialized) {
        init_gf_tables(H);
    }

    // ���ɳ�ʼ��������J0
    generate_J0(iv, iv_len, H, J0);

    // ������֤��ǩ������֤
    ghash(H, aad, aad_len, ciphertext, ciphertext_len, S);
    generate_tag(J0, S, round_keys, calculated_tag);

    // ��֤��ǩ
    bool tag_valid = true;
    for (int i = 0; i < 16; i++) {
        if (calculated_tag[i] != tag[i]) {
            tag_valid = false;
        }
    }

    // �����ǩ��Ч��������κβ��ֽ��������ʧ��
    if (!tag_valid) {
        if (ciphertext_len > 0) {
            memset(plaintext, 0, ciphertext_len);
        }
        return false;
    }

    // ���������õļ���������J0+1��ʼ
    memcpy(counter, J0, 16);
    increment_counter(counter);

    // ��������
    remaining = ciphertext_len;
    size_t total_blocks = (ciphertext_len + 15) / 16;

    // �����
    for (size_t i = 0; i < total_blocks; i++) {
        size_t block_size = (i == total_blocks - 1 && remaining < 16) ? remaining : 16;

        // ���ܼ�����
        sm4_encrypt_ttable(counter, block, round_keys);

        // ���������õ�����
        for (size_t j = 0; j < block_size; j++) {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ block[j];
        }

        // ����������
        increment_counter(counter);
        remaining -= block_size;
    }

    return true;
}