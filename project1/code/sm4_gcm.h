#pragma once
#include "sm4_shared.h"
#include <vector>
#include <cstring>

// SM4-GCM ��֤��ǩ�Ĵ�С���ֽڣ�
#define SM4_GCM_TAG_SIZE 16

// GF(2^128)�˷���Ԥ�����
extern uint64_t H_TABLE[16][256];
extern bool h_tables_initialized;

/**
 * ��ʼ��GCMģʽ��Ԥ��������GF(2^128)�˷��ı��
 * @param key 128λ������Կ
 * @param H_out ��ϣ����ԿH����ѡ���������
 */
void sm4_gcm_init(const uint8_t* key, uint8_t* H_out = nullptr);

/**
 * ִ��SM4-GCM����
 * @param key 128λ������Կ
 * @param iv ��ʼ��������nonce��
 * @param iv_len IV���ֽڳ��ȣ��Ƽ�12�ֽڣ�
 * @param aad ������֤����
 * @param aad_len AAD���ֽڳ���
 * @param plaintext �����ܵ�����
 * @param plaintext_len ���ĵ��ֽڳ���
 * @param ciphertext ���������������������Ҫplaintext_len�ֽڣ�
 * @param tag ��֤��ǩ���������������ΪSM4_GCM_TAG_SIZE�ֽڣ�
 * @return ������ܳɹ��򷵻�true
 */
bool sm4_gcm_encrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t* tag);

/**
 * ִ��SM4-GCM���ܺ���֤
 * @param key 128λ������Կ
 * @param iv ��ʼ��������nonce��
 * @param iv_len IV���ֽڳ��ȣ��Ƽ�12�ֽڣ�
 * @param aad ������֤����
 * @param aad_len AAD���ֽڳ���
 * @param ciphertext �����ܵ�����
 * @param ciphertext_len ���ĵ��ֽڳ���
 * @param plaintext ���������������������Ҫciphertext_len�ֽڣ�
 * @param tag ����֤����֤��ǩ
 * @return ������ܺͱ�ǩ��֤�ɹ��򷵻�true
 */
bool sm4_gcm_decrypt(
    const uint8_t* key,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    uint8_t* plaintext,
    const uint8_t* tag);

// �ڲ����������ڲ��Ժ͵��ԣ�

/**
 * ִ��GCMģʽ�е�GHASH����
 * @param H ��ϣ����Կ
 * @param A ������֤����
 * @param A_len AAD���ֽڳ���
 * @param C ����
 * @param C_len ���ĵ��ֽڳ���
 * @param out GHASH����������������16�ֽڣ�
 */
void ghash(
    const uint8_t* H,
    const uint8_t* A, size_t A_len,
    const uint8_t* C, size_t C_len,
    uint8_t* out);

/**
 * ʹ��Ԥ�����ִ��GF(2^128)���ϵĳ˷�
 * @param X ��һ��128λ�����
 * @param Y �ڶ���128λ�����
 * @param out 128λ�����
 */
void gf_multiply(const uint8_t* X, const uint8_t* Y, uint8_t* out);

/**
 * ����128λ��˸�ʽ�ļ�����ֵ
 * @param counter Ҫ�����ļ�������
 */
void increment_counter(uint8_t* counter);

/**
 * ����GCM�淶����IV���ɳ�ʼ��������J0
 * @param iv ��ʼ������
 * @param iv_len IV���ֽڳ���
 * @param H ��ϣ����Կ
 * @param J0 ��ʼ��������������������16�ֽڣ�
 */
void generate_J0(const uint8_t* iv, size_t iv_len, const uint8_t* H, uint8_t* J0);

/**
 * �������յ���֤��ǩ
 * @param J0 ��ʼ��������
 * @param S GHASH���
 * @param round_keys SM4����Կ
 * @param tag ��ǩ�������������16�ֽڣ�
 */
void generate_tag(const uint8_t* J0, const uint8_t* S, const uint32_t* round_keys, uint8_t* tag);

/**
 * ��ʼ�������Ż�GF(2^128)�˷���Ԥ�����
 * @param H ��ϣ����ԿH
 */
void init_gf_tables(const uint8_t* H);

/**
 * ������GF(2^128)�˷�ʵ�֣����ڱ��ʼ����
 * @param X ��һ��128λ�����
 * @param Y �ڶ���128λ�����
 * @param out 128λ�����
 */
void gf_multiply_basic(const uint8_t * X, const uint8_t * Y, uint8_t * out); 