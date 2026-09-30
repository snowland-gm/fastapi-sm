# -*- coding: utf-8 -*-
"""统一国密加解密后端注册与发现。

提供：

* ``CryptoBackend``：所有后端实现的统一接口（见 ``.base``）。
* ``get_crypto_backend(name=None)``：取可用后端实例；不指定 ``name`` 时按
  ``_DEFAULT_PROBE_ORDER`` 探测，返回第一个可用后端。
* 全局密钥配置：``set_encryption_key``（SM4 对称）、``set_sm2_keypair``
  （SM2 非对称），供字段加密等场景在应用启动时设置一次、全局生效。

后端为可选项：未安装对应底层库时，对应后端不会被注册，不会抛出 ImportError。
"""
from fastapi_sm.backends.base import (
    BackendNotAvailable,
    CryptoBackend,
    SM4_KEY_SIZE,
)

# 后端注册表与默认探测顺序。用户要求非对称优先 pysmx，故 pysmx 排在前。
_BACKEND_REGISTRY = {}
_DEFAULT_PROBE_ORDER = ("pysmx", "gmssl_pyx")

# 全局默认密钥（应用层无感加密/解密时使用）。
_default_sm4_key: bytes = b"fastapi-sm-default"  # 16 字节占位，生产须显式设置
_default_sm2_keypair = (None, None)  # (private_key, public_key)


def _load_backends():
    for name in _DEFAULT_PROBE_ORDER:
        try:
            if name == "pysmx":
                from fastapi_sm.backends.pysmx import PysmxBackend as _cls
            else:
                from fastapi_sm.backends.gmssl_pyx import (  # noqa: F811
                    GmsslPyxBackend as _cls,
                )
        except ImportError:
            # 可选后端未安装；静默跳过。
            continue
        _BACKEND_REGISTRY[name] = _cls


_load_backends()


def available_backends():
    """返回当前已注册（可用）的后端名称列表。"""
    return list(_BACKEND_REGISTRY)


def get_crypto_backend(name=None):
    """返回已初始化的统一加解密后端实例。

    若 ``name`` 省略，按 ``_DEFAULT_PROBE_ORDER`` 探测并返回第一个可用后端；
    若没有任何后端可导入，抛出 ``BackendNotAvailable``。
    """
    if name is None:
        for candidate in _DEFAULT_PROBE_ORDER:
            if candidate not in _BACKEND_REGISTRY:
                continue
            try:
                return _BACKEND_REGISTRY[candidate]()
            except ImportError:
                continue
        raise BackendNotAvailable(
            "没有任何可用的国密后端，请安装其中之一：snowland-smx (pysmx) "
            "或 gmssl-pyx。"
        )
    if name not in _BACKEND_REGISTRY:
        raise BackendNotAvailable("未知国密后端：%r" % (name,))
    try:
        return _BACKEND_REGISTRY[name]()
    except ImportError as exc:
        raise BackendNotAvailable("国密后端 %r 未安装。" % (name,)) from exc


def set_encryption_key(key) -> None:
    """设置全局默认 SM4 对称密钥（str 按 utf-8 编码，须为 16 字节）。"""
    global _default_sm4_key
    kb = key.encode("utf-8") if isinstance(key, str) else key
    if len(kb) != SM4_KEY_SIZE:
        raise ValueError(f"SM4 密钥长度必须为 {SM4_KEY_SIZE} 字节")
    _default_sm4_key = kb


def set_sm2_keypair(private_key: bytes, public_key: bytes) -> None:
    """设置全局默认 SM2 非对称密钥对 ``(private_key, public_key)``。"""
    global _default_sm2_keypair
    _default_sm2_keypair = (private_key, public_key)


def get_default_sm4_key() -> bytes:
    return _default_sm4_key


def get_default_sm2_keypair():
    return _default_sm2_keypair


__all__ = [
    "BackendNotAvailable",
    "CryptoBackend",
    "available_backends",
    "get_crypto_backend",
    "set_encryption_key",
    "set_sm2_keypair",
    "get_default_sm4_key",
    "get_default_sm2_keypair",
]
