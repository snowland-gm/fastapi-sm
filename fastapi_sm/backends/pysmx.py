# -*- coding: utf-8 -*-
"""基于 snowland-smx（``pysmx``）的国密统一后端。

仅在环境中已安装 ``snowland-smx`` 时可导入；``fastapi_sm.backends`` 会在加载时
尝试导入本模块，失败则静默跳过（后端变为可选项）。
"""

import os

from cryptography.exceptions import InvalidSignature
from pysmx.SM2 import (
    SM2EllipticCurve,
    SM2EllipticCurvePrivateKey,
    SM2EllipticCurvePublicKey,
    SM2SM3SignatureAlgorithm,
    generate_keypair,
)
from pysmx.SM4 import sm4_crypt_cbc as _sm4_crypt_cbc
from pysmx.crypto import hashlib as _sm3_hashlib

from fastapi_sm.backends.base import CryptoBackend, SM4_BLOCK_SIZE, SM4_KEY_SIZE


class PysmxBackend(CryptoBackend):
    """基于 snowland-smx（``pysmx``）的统一后端。

    SM2 签名/验签使用类 API（原始 ``r || s`` 编码），SM2 加解密与 SM3/SM4
    使用底层函数。用户此前明确要求非对称优先使用 pysmx。
    """

    name = "pysmx"

    # ---- SM3 ----
    def sm3_hash(self, data: bytes) -> bytes:
        return _sm3_hashlib.new("sm3", data).digest()

    # ---- SM2 非对称 ----
    def sm2_generate_keypair(self):
        kp = generate_keypair()
        # generate_keypair 返回 KeyPair(publicKey, privateKey)
        return kp.privateKey, kp.publicKey

    def sm2_sign(self, msg: bytes, private_key: bytes, public_key: bytes,
                 uid: bytes) -> bytes:
        key = SM2EllipticCurvePrivateKey(
            SM2EllipticCurve(), private_key, public_key
        )
        return key.sign(msg, SM2SM3SignatureAlgorithm(), uid=uid)

    def sm2_verify(self, msg: bytes, signature: bytes, public_key: bytes,
                   uid: bytes) -> bool:
        key = SM2EllipticCurvePublicKey(SM2EllipticCurve(), public_key)
        try:
            key.verify(signature, msg, SM2SM3SignatureAlgorithm(), uid=uid)
        except InvalidSignature:
            return False
        return True

    def sm2_encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        # pysmx 将 encrypt_sm2 实现在「私钥」类上，但内部仅使用其携带的公钥，
        # 私钥值不参与加密；故用占位私钥构造对象即可。
        placeholder_priv = public_key[:32] if len(public_key) >= 32 else public_key
        key = SM2EllipticCurvePrivateKey(
            SM2EllipticCurve(), placeholder_priv, public_key
        )
        cipher = key.encrypt_sm2(plaintext, hash_algorithm="sm3", mode="C1C3C2")
        if cipher is None:
            raise ValueError("SM2 加密失败（公钥或明文不合法）")
        return cipher

    def sm2_decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
        # decrypt_sm2 在「私钥」类上，内部仅使用私钥值；公钥用占位即可。
        key = SM2EllipticCurvePrivateKey(
            SM2EllipticCurve(), private_key, private_key
        )
        plain = key.decrypt_sm2(ciphertext, hash_algorithm="sm3", mode="C1C3C2")
        if plain is None:
            raise ValueError("SM2 解密失败（密文完整性校验不通过）")
        return plain

    # ---- SM4 对称 ----
    def sm4_encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        if len(key) != SM4_KEY_SIZE:
            raise ValueError(f"SM4 密钥长度必须为 {SM4_KEY_SIZE} 字节")
        iv = os.urandom(SM4_BLOCK_SIZE)
        return iv + _sm4_crypt_cbc(0, key, iv, plaintext)

    def sm4_decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        if len(key) != SM4_KEY_SIZE:
            raise ValueError(f"SM4 密钥长度必须为 {SM4_KEY_SIZE} 字节")
        iv, data = ciphertext[:SM4_BLOCK_SIZE], ciphertext[SM4_BLOCK_SIZE:]
        return _sm4_crypt_cbc(1, key, iv, data)
