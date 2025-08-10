#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import random
from sm2_params import n
from sm2_ec import G, point_multiply, mod_inverse
from sm2_keygen import generate_key_pair
from sm2_signature import sm3_hash


def recover_private_key_from_reused_k_fixed(message1, signature1, message2, signature2, Z=None):
    """
    修正版：通过重用随机数k的两个签名恢复私钥

    数学原理：
    对于SM2签名，当使用相同的k对两个不同消息签名时：

    消息1: r1 = (e1 + x1) mod n, s1 = ((1+d)^-1 * (k - r1*d)) mod n
    消息2: r2 = (e2 + x1) mod n, s2 = ((1+d)^-1 * (k - r2*d)) mod n

    其中 x1 = (k*G).x，由于使用相同的k，所以x1相同，但r1 ≠ r2（因为e1 ≠ e2）

    从签名方程可得：
    (1+d)*s1 = k - r1*d ... (1)
    (1+d)*s2 = k - r2*d ... (2)

    (1)-(2): (1+d)*(s1-s2) = (r2-r1)*d
    解得: d = (1+d)*(s1-s2)/(r2-r1) = (s1-s2)/(r2-r1) + d*(s1-s2)/(r2-r1)

    整理得: d*(1 - (s1-s2)/(r2-r1)) = (s1-s2)/(r2-r1)
    因此: d = (s1-s2)/((r2-r1) - (s1-s2))
    """
    if Z is None:
        Z = b'1234567812345678'

    r1, s1 = signature1
    r2, s2 = signature2

    # 计算两个消息的摘要
    e1 = sm3_hash(Z + message1)
    e2 = sm3_hash(Z + message2)

    # 验证是否使用了相同的k（通过x1相同来判断）
    # 由于 r1 = (e1 + x1) mod n, r2 = (e2 + x1) mod n
    # 所以 x1 = r1 - e1 mod n = r2 - e2 mod n
    x1_from_msg1 = (r1 - e1) % n
    x1_from_msg2 = (r2 - e2) % n

    if x1_from_msg1 != x1_from_msg2:
        raise ValueError("两个签名没有使用相同的随机数k")

    # 计算私钥
    numerator = (s1 - s2) % n
    denominator = ((r2 - r1) - (s1 - s2)) % n

    if denominator == 0:
        raise ValueError("分母为0，无法恢复私钥")

    # 计算 d = numerator * denominator^-1 mod n
    d = (numerator * mod_inverse(denominator, n)) % n

    return d


def generate_signatures_with_same_k(message1, message2, private_key, k, Z=None):
    """
    使用相同的随机数k为两个消息生成签名
    """
    if Z is None:
        Z = b'1234567812345678'

    # 计算 (x1,y1) = k*G
    point = point_multiply(k, G)
    x1 = point.x

    # 为第一条消息签名
    e1 = sm3_hash(Z + message1)
    r1 = (e1 + x1) % n
    s1 = (mod_inverse(1 + private_key, n) * (k - r1 * private_key % n) % n) % n
    signature1 = (r1, s1)

    # 为第二条消息签名
    e2 = sm3_hash(Z + message2)
    r2 = (e2 + x1) % n
    s2 = (mod_inverse(1 + private_key, n) * (k - r2 * private_key % n) % n) % n
    signature2 = (r2, s2)

    return signature1, signature2


def poc_reuse_k_fixed():
    """修正版重用随机数k的漏洞POC验证"""
    print("=" * 50)
    print("修正版：SM2重用随机数k的漏洞POC验证")
    print("=" * 50)

    # 1. 生成密钥对
    d, P = generate_key_pair()
    print(f"原始私钥 d = {hex(d)}")

    # 2. 为两个不同的消息使用相同的随机数k生成签名
    k = random.randint(1, n - 2)
    print(f"重用的随机数 k = {hex(k)}")

    message1 = b"First message for SM2 signature test"
    message2 = b"Second message for SM2 signature test"

    # 生成签名
    signature1, signature2 = generate_signatures_with_same_k(message1, message2, d, k)

    r1, s1 = signature1
    r2, s2 = signature2
    print(f"消息1的签名 (r1,s1) = ({hex(r1)}, {hex(s1)})")
    print(f"消息2的签名 (r2,s2) = ({hex(r2)}, {hex(s2)})")

    # 3. 尝试恢复私钥
    try:
        recovered_d = recover_private_key_from_reused_k_fixed(message1, signature1, message2, signature2)
        print(f"恢复的私钥 d = {hex(recovered_d)}")

        # 4. 验证恢复的私钥是否正确
        if d == recovered_d:
            print("✅ 私钥恢复成功！原始私钥和恢复的私钥相同。")
        else:
            print("❌ 私钥恢复失败！")

    except Exception as e:
        print(f"❌ 恢复过程出错: {e}")

    print("\n数学原理说明:")
    print("当重用随机数k时，虽然r1 ≠ r2，但x1相同")
    print("利用签名方程的差值可以消除k，从而求解出私钥d")
    print("推导公式: d = (s1-s2)/((r2-r1)-(s1-s2)) mod n")


def main():
    """主函数"""
    poc_reuse_k_fixed()


if __name__ == "__main__":
    main()