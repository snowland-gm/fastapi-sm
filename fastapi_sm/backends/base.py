# -*- coding: utf-8 -*-
"""国密统一加解密后端抽象基类。

所有后端（``pysmx`` / ``gmssl_pyx``）实现同一套接口，覆盖：

* SM3：哈希（``sm3_hash``）、HMAC（``hmac_sm3``）
* SM2：密钥对生成（``sm2_generate_keypair``）、签名/验签
  （``sm2_sign`` / ``sm2_verify``）、加解密（``sm2_encrypt`` / ``sm2_decrypt``）
* SM4：对称加解密（``sm4_encrypt`` / ``sm4_decrypt``）

密钥一律以原始 ``bytes`` 传递：SM2 私钥为 32 字节标量 ``d``，SM4 密钥为
16 字节；SM2 公钥为各后端约定的原始公钥字节（不同后端之间不保证可互验，
与 snowland-jwt 的约束一致）。
"""
from abc import ABC, ABCMeta

try:
    from snowland_jwt.backends import CryptoBackend as _CryptoBackend
except ImportError:
    # snowland-jwt 是本包的声明依赖，正常环境由安装流程自动安装并使用其基类；
    # 此处仅在其缺失时兜底，避免整包因该依赖未装而导入失败。后端选择仍按
    # 实际可用的底层库（snowland-smx / gmssl-pyx）自动挑选。
    _CryptoBackend = ABC

# SM3 摘要长度（字节）
SM3_DIGEST_SIZE = 32
# HMAC 分组长度（SM3 分组 64 字节，与 PKCS#5 一致）
HMAC_BLOCK_SIZE = 64
# SM4 密钥 / 分组大小（字节）
SM4_KEY_SIZE = 16
SM4_BLOCK_SIZE = 16


class BackendNotAvailable(Exception):
    """当没有任何（或请求的）加解密后端可导入时抛出。"""


class CryptoBackend(_CryptoBackend, metaclass=ABCMeta):
    """国密统一后端必须实现的接口。

    约定：``encrypt`` 类方法返回的结果自带恢复所需的所有随机量（如 SM4 的
    IV 已拼接到密文头部），``decrypt`` 时无需额外传参。
    """

    name = "abstract"

    # ---- SM3 ----
    def sm3_hash(self, data: bytes) -> bytes:
        raise NotImplementedError

    def hmac_sm3(self, key: bytes, msg: bytes) -> bytes:
        """HMAC-SM3，基于本后端的 ``sm3_hash`` 实现（与具体后端无关）。"""
        return _hmac_with(self.sm3_hash, key, msg)

    # ---- SM2 非对称 ----
    def sm2_generate_keypair(self):
        """返回 ``(private_key: bytes, public_key: bytes)``。"""
        raise NotImplementedError

    def sm2_sign(self, msg: bytes, private_key: bytes, public_key: bytes,
                 uid: bytes) -> bytes:
        raise NotImplementedError

    def sm2_verify(self, msg: bytes, signature: bytes, public_key: bytes,
                   uid: bytes) -> bool:
        raise NotImplementedError

    def sm2_encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def sm2_decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
        raise NotImplementedError

    # ---- SM4 对称 ----
    def sm4_encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def sm4_decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        raise NotImplementedError


def _hmac_with(hash_func, key: bytes, msg: bytes) -> bytes:
    """通用 HMAC，PRF 由 ``hash_func`` 提供（块大小按 SM3 的 64 字节）。"""
    if len(key) > HMAC_BLOCK_SIZE:
        key = hash_func(key)
    key = key + b"\x00" * (HMAC_BLOCK_SIZE - len(key))
    outer = bytes(b ^ 0x5C for b in key)
    inner = bytes(b ^ 0x36 for b in key)
    return hash_func(outer + hash_func(inner + msg))
