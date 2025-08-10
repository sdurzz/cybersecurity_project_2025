# -*- coding: utf-8 -*-
"""
Google Password Checkup Implementation (Improved Version)

基于论文 "On Deploying Secure Computing: Private Intersection-Sum-with-Cardinality"
的 Section 3.1 协议实现，提供隐私保护的密码泄露检测服务。

Author: Improved Implementation
Date: 2024
"""

import hashlib
import logging
import os
import secrets
from dataclasses import dataclass
from typing import Set, List, Tuple, Optional, Union
from enum import Enum

from tinyec import registry
from tinyec.ec import Point


# ==================== 配置和常量 ====================

@dataclass(frozen=True)
class Config:
    """系统配置类"""
    CURVE_NAME: str = 'secp256r1'
    PREFIX_LENGTH_BYTES: int = 4
    HASH_ALGORITHM: str = 'sha256'
    MAX_HASH_TO_CURVE_ATTEMPTS: int = 1000
    DEFAULT_RANDOM_BYTES: int = 32


class LogLevel(Enum):
    """日志级别枚举"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


# ==================== 异常定义 ====================

class PasswordCheckupError(Exception):
    """密码检查服务基础异常"""
    pass


class CryptographicError(PasswordCheckupError):
    """密码学操作异常"""
    pass


class InvalidInputError(PasswordCheckupError):
    """无效输入异常"""
    pass


class HashToCurveError(CryptographicError):
    """Hash-to-Curve操作异常"""
    pass


# ==================== 工具函数 ====================

def setup_logging(level: LogLevel = LogLevel.INFO) -> logging.Logger:
    """设置日志系统"""
    logging.basicConfig(
        level=getattr(logging, level.value),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)


def validate_input(username: str, password: str) -> None:
    """验证用户输入"""
    if not isinstance(username, str) or not username.strip():
        raise InvalidInputError("用户名不能为空")
    if not isinstance(password, str) or not password:
        raise InvalidInputError("密码不能为空")
    if len(username) > 255:
        raise InvalidInputError("用户名过长")
    if len(password) > 1000:
        raise InvalidInputError("密码过长")


def secure_random_int(max_value: int) -> int:
    """生成安全的随机整数"""
    if max_value <= 0:
        raise ValueError("最大值必须为正数")
    return secrets.randbelow(max_value)


# ==================== 密码学操作 ====================

class CryptographicOperations:
    """密码学操作类"""

    def __init__(self, config: Config):
        self.config = config
        self.curve = registry.get_curve(config.CURVE_NAME)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def h1(self, username: str, password: str) -> bytes:
        """
        哈希函数 H1: 将用户名和密码组合并哈希

        Args:
            username: 用户名
            password: 密码

        Returns:
            哈希结果
        """
        try:
            validate_input(username, password)

            username_bytes = username.encode('utf-8')
            password_bytes = password.encode('utf-8')

            hasher = hashlib.new(self.config.HASH_ALGORITHM)
            hasher.update(b"username:" + username_bytes)
            hasher.update(b"password:" + password_bytes)

            return hasher.digest()

        except Exception as e:
            raise CryptographicError(f"H1哈希计算失败: {e}")

    def h2_hash_to_curve(self, data: bytes) -> Point:
        """
        哈希函数 H2: 将字节串映射到椭圆曲线上的点

        Args:
            data: 待映射的数据

        Returns:
            椭圆曲线上的点

        Raises:
            HashToCurveError: 当无法找到有效点时
        """
        if not isinstance(data, bytes):
            raise InvalidInputError("输入数据必须是字节类型")

        attempts = 0
        working_data = data

        while attempts < self.config.MAX_HASH_TO_CURVE_ATTEMPTS:
            try:
                # 生成候选的 x 坐标
                x_bytes = hashlib.new(self.config.HASH_ALGORITHM, working_data).digest()
                x = int.from_bytes(x_bytes, 'big') % self.curve.field.p

                # 计算椭圆曲线方程右边: y^2 = x^3 + ax + b (mod p)
                y_squared = (pow(x, 3, self.curve.field.p) +
                             self.curve.a * x + self.curve.b) % self.curve.field.p

                # 检查是否为二次剩余
                if pow(y_squared, (self.curve.field.p - 1) // 2, self.curve.field.p) == 1:
                    # 计算平方根（适用于 p ≡ 3 (mod 4)）
                    y = pow(y_squared, (self.curve.field.p + 1) // 4, self.curve.field.p)

                    # 验证点是否在曲线上
                    point = Point(self.curve, x, y)
                    if self._is_valid_point(point):
                        self.logger.debug(f"Hash-to-curve 成功，尝试次数: {attempts + 1}")
                        return point

                # 如果失败，修改输入数据重试
                working_data += bytes([attempts % 256])
                attempts += 1

            except Exception as e:
                self.logger.warning(f"Hash-to-curve 尝试 {attempts + 1} 失败: {e}")
                working_data += bytes([attempts % 256])
                attempts += 1

        raise HashToCurveError(f"在 {self.config.MAX_HASH_TO_CURVE_ATTEMPTS} 次尝试后无法生成有效点")

    def _is_valid_point(self, point: Point) -> bool:
        """验证点是否在椭圆曲线上"""
        try:
            x, y = point.x, point.y
            left = (y * y) % self.curve.field.p
            right = (pow(x, 3, self.curve.field.p) +
                     self.curve.a * x + self.curve.b) % self.curve.field.p
            return left == right
        except:
            return False

    def point_to_bytes(self, point: Point) -> bytes:
        """将椭圆曲线点序列化为字节串"""
        try:
            coord_size = (self.curve.field.n.bit_length() + 7) // 8
            return (point.x.to_bytes(coord_size, 'big') +
                    point.y.to_bytes(coord_size, 'big'))
        except Exception as e:
            raise CryptographicError(f"点序列化失败: {e}")

    def bytes_to_point(self, data: bytes) -> Point:
        """从字节串反序列化椭圆曲线点"""
        try:
            coord_size = (self.curve.field.n.bit_length() + 7) // 8
            if len(data) != 2 * coord_size:
                raise InvalidInputError(f"数据长度错误，期望 {2 * coord_size}，实际 {len(data)}")

            x = int.from_bytes(data[:coord_size], 'big')
            y = int.from_bytes(data[coord_size:], 'big')

            point = Point(self.curve, x, y)
            if not self._is_valid_point(point):
                raise CryptographicError("反序列化的点不在椭圆曲线上")

            return point
        except Exception as e:
            raise CryptographicError(f"点反序列化失败: {e}")

    def generate_private_key(self) -> int:
        """生成安全的私钥"""
        return secure_random_int(self.curve.field.n)


# ==================== 服务器类 ====================

class PasswordCheckupServer:
    """密码检查服务器类"""

    def __init__(self, breached_credentials: Set[Tuple[str, str]], config: Optional[Config] = None):
        """
        初始化服务器

        Args:
            breached_credentials: 泄露的凭据集合 (用户名, 密码)
            config: 配置对象
        """
        self.config = config or Config()
        self.crypto = CryptographicOperations(self.config)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # 验证输入
        if not isinstance(breached_credentials, set):
            raise InvalidInputError("泄露凭据必须是集合类型")

        if not breached_credentials:
            raise InvalidInputError("泄露凭据集合不能为空")

        self._initialize_server(breached_credentials)

    def _initialize_server(self, breached_credentials: Set[Tuple[str, str]]) -> None:
        """初始化服务器内部状态"""
        self.logger.info("=== [服务器] 初始化开始 ===")

        try:
            # 生成服务器私钥
            self._private_key = self.crypto.generate_private_key()
            self.logger.info("[服务器] 私钥生成完成")

            # 预处理泄露凭据
            self._breached_prf_values = {}
            self.logger.info(f"[服务器] 开始预处理 {len(breached_credentials)} 条泄露凭据")

            processed_count = 0
            for username, password in breached_credentials:
                try:
                    # 验证凭据格式
                    validate_input(username, password)

                    # 计算 PRF 值
                    y = self.crypto.h1(username, password)
                    h2_y = self.crypto.h2_hash_to_curve(y)
                    v_y_point = self._private_key * h2_y
                    v_y_bytes = self.crypto.point_to_bytes(v_y_point)

                    # 存储前缀
                    prefix = v_y_bytes[:self.config.PREFIX_LENGTH_BYTES]
                    if prefix not in self._breached_prf_values:
                        self._breached_prf_values[prefix] = []
                    self._breached_prf_values[prefix].append(v_y_bytes)

                    processed_count += 1

                except Exception as e:
                    self.logger.warning(f"处理凭据 ({username}, ***) 失败: {e}")
                    continue

            self.logger.info(f"[服务器] 预处理完成，成功处理 {processed_count} 条凭据")
            self.logger.info(f"[服务器] 生成 {len(self._breached_prf_values)} 个唯一前缀")
            self.logger.info("=== [服务器] 初始化结束 ===")

        except Exception as e:
            raise PasswordCheckupError(f"服务器初始化失败: {e}")

    def get_breached_prf_prefixes(self) -> List[bytes]:
        """获取所有泄露凭据的PRF值前缀列表"""
        self.logger.debug("[服务器] 收到客户端请求，返回PRF前缀列表")
        return list(self._breached_prf_values.keys())

    def handle_blinded_request(self, blinded_point_bytes: bytes) -> bytes:
        """
        处理客户端的盲化请求

        Args:
            blinded_point_bytes: 盲化后的点（字节格式）

        Returns:
            服务器计算结果（字节格式）
        """
        try:
            self.logger.debug("[服务器] 收到盲化请求")

            # 反序列化盲化点
            blinded_point = self.crypto.bytes_to_point(blinded_point_bytes)

            # 计算 Z = k * T
            result_point = self._private_key * blinded_point

            # 序列化结果
            result_bytes = self.crypto.point_to_bytes(result_point)

            self.logger.debug("[服务器] 盲化请求处理完成")
            return result_bytes

        except Exception as e:
            raise CryptographicError(f"处理盲化请求失败: {e}")

    def get_full_hashes_for_prefix(self, prefix: bytes) -> List[bytes]:
        """根据前缀获取完整哈希列表"""
        if not isinstance(prefix, bytes):
            raise InvalidInputError("前缀必须是字节类型")

        self.logger.debug(f"[服务器] 查询前缀 {prefix.hex()} 的完整哈希")
        return self._breached_prf_values.get(prefix, [])


# ==================== 客户端类 ====================

class PasswordCheckupClient:
    """密码检查客户端类"""

    def __init__(self, username: str, password: str, config: Optional[Config] = None):
        """
        初始化客户端

        Args:
            username: 用户名
            password: 密码
            config: 配置对象
        """
        self.config = config or Config()
        self.crypto = CryptographicOperations(self.config)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # 验证并存储凭据
        validate_input(username, password)
        self.username = username
        self.password = password

        self.logger.info(f"=== [客户端] 初始化完成，用户: '{self.username}' ===")

    def check_password_leak(self, server: PasswordCheckupServer) -> bool:
        """
        检查密码是否泄露

        Args:
            server: 服务器实例

        Returns:
            True 如果密码已泄露，False 否则
        """
        try:
            self.logger.info(f"[客户端] 开始检查用户 '{self.username}' 的密码")

            # 第一步：客户端盲化
            blinding_result = self._perform_blinding()

            # 第二步：与服务器交互
            server_result = self._interact_with_server(server, blinding_result)

            # 第三步：去盲化和验证
            is_leaked = self._unblind_and_verify(server, blinding_result, server_result)

            result_str = "已泄露" if is_leaked else "安全"
            self.logger.info(f"=== [结论] 用户 '{self.username}' 的凭据{result_str} ===")

            return is_leaked

        except Exception as e:
            self.logger.error(f"密码检查过程出错: {e}")
            raise PasswordCheckupError(f"密码检查失败: {e}")

    def _perform_blinding(self) -> dict:
        """执行盲化步骤"""
        try:
            self.logger.debug("[客户端] 步骤1: 开始盲化")

            # 计算凭据哈希
            x = self.crypto.h1(self.username, self.password)
            self.logger.debug(f"[客户端] 计算H1(u,p) = {x.hex()}")

            # 映射到曲线点
            P = self.crypto.h2_hash_to_curve(x)
            self.logger.debug("[客户端] 完成Hash-to-Curve映射")

            # 生成盲化因子
            t = self.crypto.generate_private_key()
            self.logger.debug("[客户端] 生成盲化因子")

            # 计算盲化点
            T = t * P
            T_bytes = self.crypto.point_to_bytes(T)
            self.logger.debug("[客户端] 计算盲化点完成")

            return {
                'blinding_factor': t,
                'original_point': P,
                'blinded_point_bytes': T_bytes
            }

        except Exception as e:
            raise CryptographicError(f"盲化步骤失败: {e}")

    def _interact_with_server(self, server: PasswordCheckupServer, blinding_result: dict) -> bytes:
        """与服务器交互"""
        try:
            self.logger.debug("[客户端] 步骤2: 与服务器交互")

            # 发送盲化请求
            result = server.handle_blinded_request(blinding_result['blinded_point_bytes'])

            self.logger.debug("[客户端] 服务器交互完成")
            return result

        except Exception as e:
            raise CryptographicError(f"服务器交互失败: {e}")

    def _unblind_and_verify(self, server: PasswordCheckupServer,
                            blinding_result: dict, server_result: bytes) -> bool:
        """去盲化并验证结果"""
        try:
            self.logger.debug("[客户端] 步骤3: 去盲化和验证")

            # 计算盲化因子的逆元
            t = blinding_result['blinding_factor']
            t_inv = pow(t, -1, self.crypto.curve.field.n)
            self.logger.debug("[客户端] 计算盲化因子逆元")

            # 去盲化
            Z_point = self.crypto.bytes_to_point(server_result)
            V_point = t_inv * Z_point
            V_bytes = self.crypto.point_to_bytes(V_point)
            self.logger.debug(f"[客户端] 去盲化得到PRF值: {V_bytes.hex()}")

            # 获取泄露数据前缀
            leaked_prefixes = server.get_breached_prf_prefixes()
            self.logger.debug(f"[客户端] 获取到 {len(leaked_prefixes)} 个泄露前缀")

            # 检查前缀匹配
            my_prefix = V_bytes[:self.config.PREFIX_LENGTH_BYTES]
            self.logger.debug(f"[客户端] 本地PRF前缀: {my_prefix.hex()}")

            if my_prefix not in leaked_prefixes:
                self.logger.debug("[客户端] 前缀不匹配，密码安全")
                return False

            self.logger.debug("[客户端] 前缀匹配，进行完整验证")

            # 获取完整哈希进行最终验证
            full_hashes = server.get_full_hashes_for_prefix(my_prefix)

            if V_bytes in full_hashes:
                self.logger.debug("[客户端] 完整PRF值匹配，密码已泄露")
                return True
            else:
                self.logger.debug("[客户端] 完整PRF值不匹配，这是前缀碰撞，密码安全")
                return False

        except Exception as e:
            raise CryptographicError(f"去盲化和验证失败: {e}")


# ==================== 测试和演示 ====================

def create_test_database() -> Set[Tuple[str, str]]:
    """创建测试用的泄露数据库"""
    return {
        ("alice", "123456"),
        ("bob", "password"),
        ("charlie", "qwerty"),
        ("david", "google-sucks"),
        ("eve_test", "leaked_password")
    }


def run_demonstration():
    """运行演示程序"""
    # 设置日志
    logger = setup_logging(LogLevel.INFO)

    try:
        logger.info("开始 Google Password Checkup 演示")

        # 创建测试数据库
        breached_database = create_test_database()
        logger.info(f"创建包含 {len(breached_database)} 条记录的测试泄露数据库")

        # 初始化服务器
        server = PasswordCheckupServer(breached_database)

        # 测试场景1：检查已泄露的密码
        print("\n" + "=" * 50)
        print("测试场景1: 检查已泄露的密码 ('alice', '123456')")
        print("=" * 50)

        client_leaked = PasswordCheckupClient("alice", "123456")
        is_leaked_1 = client_leaked.check_password_leak(server)

        assert is_leaked_1 == True, "应该检测出密码已泄露"
        print(f"✅ 测试通过：密码确实已泄露")

        # 测试场景2：检查安全的密码
        print("\n" + "=" * 50)
        print("测试场景2: 检查安全的密码 ('eve', 'MySecurePa$$w0rd')")
        print("=" * 50)

        client_safe = PasswordCheckupClient("eve", "MySecurePa$$w0rd")
        is_leaked_2 = client_safe.check_password_leak(server)

        assert is_leaked_2 == False, "应该检测出密码是安全的"
        print(f"✅ 测试通过：密码确实安全")

        # 测试场景3：边界情况测试
        print("\n" + "=" * 50)
        print("测试场景3: 已知泄露用户的其他密码")
        print("=" * 50)

        client_different = PasswordCheckupClient("alice", "different_password")
        is_leaked_3 = client_different.check_password_leak(server)

        assert is_leaked_3 == False, "不同密码应该是安全的"
        print(f"✅ 测试通过：即使用户名相同，不同密码仍然安全")

        logger.info("🎉 所有测试通过！演示完成")

    except Exception as e:
        logger.error(f"演示过程中出错: {e}")
        raise


def test_error_handling():
    """测试错误处理"""
    logger = setup_logging(LogLevel.DEBUG)
    logger.info("开始错误处理测试")

    # 测试无效输入
    try:
        PasswordCheckupClient("", "password")
        assert False, "应该抛出异常"
    except InvalidInputError:
        logger.info("✅ 空用户名检测正常")

    try:
        PasswordCheckupClient("user", "")
        assert False, "应该抛出异常"
    except InvalidInputError:
        logger.info("✅ 空密码检测正常")

    # 测试空数据库
    try:
        PasswordCheckupServer(set())
        assert False, "应该抛出异常"
    except InvalidInputError:
        logger.info("✅ 空数据库检测正常")

    logger.info("✅ 错误处理测试完成")


if __name__ == "__main__":
    try:
        # 运行主演示
        run_demonstration()

        # 运行错误处理测试
        test_error_handling()

        print("\n🎉 程序执行完成！")

    except Exception as e:
        print(f"❌ 程序执行失败: {e}")
        raise