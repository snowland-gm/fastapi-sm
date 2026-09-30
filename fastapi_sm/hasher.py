# -*- coding: utf-8 -*-

import hmac
import os
from abc import ABC, abstractmethod

from fastapi_sm.backends import get_crypto_backend


# SM3 摘要长度 32 字节
SM3_DIGEST_SIZE = 32
# HMAC 分组长度（SM3 分组 64 字节，与 PKCS#5 一致）
_HMAC_BLOCK_SIZE = 64
# 推荐 salt 长度 16 字节
DEFAULT_SALT_BYTES = 16
# PBKDF2 迭代次数（可按硬件性能调整）
DEFAULT_ITERATIONS = 100_000


def _hmac_sm3(key: bytes, msg: bytes, backend) -> bytes:
    """基于 SM3 的 HMAC（标准算法，分组长度 64）。"""
    if len(key) > _HMAC_BLOCK_SIZE:
        key = backend.sm3_hash(key)
    key = key + b"\x00" * (_HMAC_BLOCK_SIZE - len(key))
    outer = bytes(b ^ 0x5C for b in key)
    inner = bytes(b ^ 0x36 for b in key)
    return backend.sm3_hash(outer + backend.sm3_hash(inner + msg))


def _pbkdf2_sm3(password, salt: bytes, iterations: int,
                backend=None) -> bytes:
    """PBKDF2-HMAC-SM3 密钥派生。

    基于 ``fastapi_sm.backends`` 提供的统一 ``sm3_hash`` 实现，与 pysmx /
    gmssl_pyx 各自产出的 PBKDF2 结果一致，可无缝校验既有哈希。
    """
    if backend is None:
        backend = get_crypto_backend()
    pw = password.encode("utf-8") if isinstance(password, str) else password
    blocks = (SM3_DIGEST_SIZE * 1 + SM3_DIGEST_SIZE - 1) // SM3_DIGEST_SIZE
    out = b""
    for i in range(1, blocks + 1):
        u = _hmac_sm3(pw, salt + i.to_bytes(4, "big"), backend)
        acc = bytearray(u)
        for _ in range(2, iterations + 1):
            u = _hmac_sm3(pw, u, backend)
            acc = bytearray(a ^ b for a, b in zip(acc, u))
        out += bytes(acc)
    # dklen 固定为 SM3_DIGEST_SIZE
    return out[:SM3_DIGEST_SIZE]


class BasePasswordHasher(ABC):
    algorithm: str

    @abstractmethod
    def salt(self) -> str:
        """生成随机 salt（hex 字符串）。"""

    @abstractmethod
    def encode(self, password: str, salt: str = None) -> str:
        """将明文口令编码为 4 段哈希字符串。"""

    @abstractmethod
    def verify(self, password: str, encoded: str) -> bool:
        """校验明文口令与已存储哈希是否匹配。"""

    @abstractmethod
    def must_update(self, encoded: str) -> bool:
        """是否需要重哈希（算法变更或迭代次数偏低）。"""

    @abstractmethod
    def safe_summary(self, encoded: str) -> dict:
        """返回用于日志/调试的脱敏摘要。"""


class SM3PasswordHasher(BasePasswordHasher):
    """基于 SM3 + PBKDF2 的口令哈希器。"""

    algorithm = "sm3_pbkdf2"

    def __init__(self, iterations: int = DEFAULT_ITERATIONS):
        self.iterations = iterations

    def salt(self) -> str:
        return os.urandom(DEFAULT_SALT_BYTES).hex()

    def encode(self, password: str, salt: str = None) -> str:
        if salt is None:
            salt = self.salt()
        dk = _pbkdf2_sm3(password, bytes.fromhex(salt), self.iterations)
        return f"{self.algorithm}${self.iterations}${salt}${dk.hex()}"

    def verify(self, password: str, encoded: str) -> bool:
        try:
            algorithm, iterations_s, salt, hash_hex = encoded.split("$")
            if algorithm != self.algorithm:
                return False
            iterations = int(iterations_s)
            expected = _pbkdf2_sm3(password, bytes.fromhex(salt), iterations)
        except (ValueError, AttributeError):
            return False
        try:
            return hmac.compare_digest(bytes.fromhex(hash_hex), expected)
        except (ValueError, AttributeError):
            return False

    def must_update(self, encoded: str) -> bool:
        try:
            algorithm, iterations_s, _, _ = encoded.split("$")
            if algorithm != self.algorithm:
                return True
            return int(iterations_s) < self.iterations
        except (ValueError, AttributeError):
            return True

    def safe_summary(self, encoded: str) -> dict:
        try:
            algorithm, iterations_s, salt, hash_hex = encoded.split("$")
            show = 6
            masked_salt = salt[:show] + "*" * max(len(salt) - show, 0)
            return {
                "algorithm": algorithm,
                "iterations": int(iterations_s),
                "salt": masked_salt,
                "hash": "*" * len(hash_hex),
            }
        except (ValueError, AttributeError):
            return {"algorithm": "invalid"}
