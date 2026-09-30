# -*- coding: utf-8 -*-
"""Tortoise-ORM 自定义字段：透明加密的 CharField。

``EncryptedString`` 继承 ``tortoise.fields.CharField``，对应用层表现为普通
字符串，但在存储层自动用国密算法加密，读出时自动解密。加密算法通过统一后端
（``fastapi_sm.backends``）提供，支持：

* 对称（``mode="symmetric"``，默认）：SM4-CBC，密文 = base64(iv || ciphertext)
* 非对称（``mode="asymmetric"``）：SM2 加密

密钥一律由构造参数 ``key`` 提供，且严格使用 ``self.key``，不从全局默认密钥
取用——因为加密/签名密钥本就不同，且密钥需要随业务轮换。约定：``self.key``
在对称模式下为 SM4 密钥字节（16 字节）；在非对称模式下为 SM2 密钥对
``(private_key, public_key)`` 元组。调用方在应用层无感。
"""

import base64

from tortoise.fields import CharField

from fastapi_sm.backends import get_crypto_backend

_SM4_KEY_SIZE = 16


class EncryptedString(CharField):
    """透明的加密字符串字段，继承 CharField。

    写入数据库前自动加密为密文字符串，读出后自动解密。应用层以普通 ``str``
    读写，存储层为密文字符串。

    :param key: 密钥（必填，不再使用全局默认）。
        对称模式为 SM4 密钥字节（16 字节）；
        非对称模式为 SM2 密钥对 ``(private_key, public_key)`` 元组（均为字节）。
    :param mode: ``"symmetric"``（SM4，默认）或 ``"asymmetric"``（SM2）。
    :param max_length: 列长度，需足够容纳 base64 密文（CharField 必填）。
    """

    def __init__(self, key=None, mode: str = "symmetric", max_length: int = 512,
                 **kwargs):
        if key is None:
            raise ValueError(
                "EncryptedString 必须显式提供 key（对称=SM4 密钥字节，"
                "非对称=SM2 (private, public) 元组），不从全局默认密钥取用。"
            )
        self.key = key
        self.mode = mode
        self._check_key()  # 提前校验，避免运行期才发现配置错误
        super().__init__(max_length=max_length, **kwargs)

    def _check_key(self) -> None:
        if self.mode == "asymmetric":
            if not isinstance(self.key, (tuple, list)) or len(self.key) != 2:
                raise ValueError("非对称模式 key 须为 (private_key, public_key) 元组")
            for part in self.key:
                if not isinstance(part, (bytes, bytearray)):
                    raise ValueError("非对称模式密钥对须均为字节")
        else:
            if not isinstance(self.key, (bytes, bytearray)):
                raise ValueError("对称模式 key 须为 SM4 密钥字节（16 字节）")
            if len(self.key) != _SM4_KEY_SIZE:
                raise ValueError("SM4 密钥长度必须为 16 字节")

    def _sm4_key(self) -> bytes:
        return bytes(self.key)

    def _asym_keypair(self):
        return bytes(self.key[0]), bytes(self.key[1])

    def to_db_value(self, value, instance):
        """应用层 -> 数据库：明文加密为密文字符串。"""
        if value is None:
            return None
        if not isinstance(value, str):
            value = str(value)
        backend = get_crypto_backend()
        data = value.encode("utf-8")
        if self.mode == "asymmetric":
            _, public_key = self._asym_keypair()
            cipher = backend.sm2_encrypt(public_key, data)
        else:
            cipher = backend.sm4_encrypt(self._sm4_key(), data)
        return base64.b64encode(cipher).decode("ascii")

    def to_python_value(self, value):
        """数据库 -> 应用层：密文字符串解密为明文。"""
        if value is None:
            return None
        raw = base64.b64decode(value)
        backend = get_crypto_backend()
        if self.mode == "asymmetric":
            private_key, _ = self._asym_keypair()
            plain = backend.sm2_decrypt(private_key, raw)
        else:
            plain = backend.sm4_decrypt(self._sm4_key(), raw)
        return plain.decode("utf-8")
