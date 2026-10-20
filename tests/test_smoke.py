# -*- coding: utf-8 -*-
"""最小冒烟测试：不依赖数据库连接，覆盖后端、口令哈希与透明加密字段。"""
import pytest

from fastapi_sm.backends import (
    available_backends,
    get_crypto_backend,
)
from fastapi_sm.hasher import SM3PasswordHasher


def test_at_least_one_backend():
    backends = available_backends()
    assert backends, "至少需要安装一个国密后端（snowland-smx 或 gmssl-pyx）"


def test_sm3_hash():
    backend = get_crypto_backend()
    digest = backend.sm3_hash(b"hello")
    assert isinstance(digest, bytes)
    assert len(digest) == 32


@pytest.mark.parametrize("name", available_backends())
def test_sm4_roundtrip_per_backend(name):
    backend = get_crypto_backend(name)
    key = b"0123456789abcdef"
    cipher = backend.sm4_encrypt(key, b"plain-text")
    assert cipher != b"plain-text"
    assert backend.sm4_decrypt(key, cipher) == b"plain-text"


def test_password_hasher():
    hasher = SM3PasswordHasher()
    encoded = hasher.encode("secret123")
    assert hasher.verify("secret123", encoded)
    assert not hasher.verify("wrong-password", encoded)
    assert hasher.safe_summary(encoded)["algorithm"] == "sm3_pbkdf2"


def test_sqlalchemy_encrypted_string():
    from fastapi_sm.database import EncryptedString

    if EncryptedString is None:
        pytest.skip("SQLAlchemy 未安装")
    # 对称：key 为 SM4 密钥字节
    col = EncryptedString(key=b"0123456789abcdef", length=512)
    to_db = col.process_bind_param("13800138000", None)
    assert to_db != "13800138000"
    assert col.process_result_value(to_db, None) == "13800138000"
    # 缺 key 必须报错
    with pytest.raises(ValueError):
        EncryptedString(length=512)


def test_tortoise_encrypted_string():
    from fastapi_sm.database import TortoiseEncryptedString

    if TortoiseEncryptedString is None:
        pytest.skip("Tortoise-ORM 未安装")
    col = TortoiseEncryptedString(key=b"0123456789abcdef", max_length=512)
    to_db = col.to_db_value("13800138000", None)
    assert to_db != "13800138000"
    assert col.to_python_value(to_db) == "13800138000"
    with pytest.raises(ValueError):
        TortoiseEncryptedString(max_length=512)
