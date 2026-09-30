# -*- coding: utf-8 -*-
"""基于 ``gmssl-pyx``（GmSSL 原生绑定）的国密统一后端。

仅在环境中已安装 ``gmssl-pyx`` 时可导入；``fastapi_sm.backends`` 会在加载时
尝试导入本模块，失败则静默跳过（后端变为可选项）。
"""

import os

from gmssl_pyx import (
    sm2_decrypt,
    sm2_encrypt,
    sm2_key_generate,
    sm2_sign,
    sm2_verify,
    sm3_hash,
    sm4_cbc_padding_decrypt,
    sm4_cbc_padding_encrypt,
)

from fastapi_sm.backends.base import CryptoBackend, SM4_BLOCK_SIZE, SM4_KEY_SIZE


class GmsslPyxBackend(CryptoBackend):
    """基于 ``gmssl-pyx``（libgmssl 原生绑定）的统一后端。"""

    name = "gmssl_pyx"

    # ---- SM3 ----
    def sm3_hash(self, data: bytes) -> bytes:
        return sm3_hash(data)

    # ---- SM2 非对称 ----
    def sm2_generate_keypair(self):
        public_key, private_key = sm2_key_generate()
        return private_key, public_key

    def sm2_sign(self, msg: bytes, private_key: bytes, public_key: bytes,
                 uid: bytes) -> bytes:
        return sm2_sign(private_key, public_key, msg, uid)

    def sm2_verify(self, msg: bytes, signature: bytes, public_key: bytes,
                   uid: bytes) -> bool:
        return sm2_verify(public_key, msg, signature, uid)

    def sm2_encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        return sm2_encrypt(public_key, plaintext)

    def sm2_decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
        return sm2_decrypt(private_key, ciphertext)

    # ---- SM4 对称 ----
    def sm4_encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        if len(key) != SM4_KEY_SIZE:
            raise ValueError(f"SM4 密钥长度必须为 {SM4_KEY_SIZE} 字节")
        iv = os.urandom(SM4_BLOCK_SIZE)
        return iv + sm4_cbc_padding_encrypt(key, iv, plaintext)

    def sm4_decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        if len(key) != SM4_KEY_SIZE:
            raise ValueError(f"SM4 密钥长度必须为 {SM4_KEY_SIZE} 字节")
        iv, data = ciphertext[:SM4_BLOCK_SIZE], ciphertext[SM4_BLOCK_SIZE:]
        return sm4_cbc_padding_decrypt(key, iv, data)
