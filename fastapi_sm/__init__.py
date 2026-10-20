# -*- coding: utf-8 -*-


__version__ = "0.1"

from fastapi_sm.hasher import BasePasswordHasher, SM3PasswordHasher
from fastapi_sm.database import (
    AbstractUser,
    User,
    Base,
    SQLALCHEMY_AVAILABLE,
    TORTOISE_AVAILABLE,
)
from fastapi_sm.backends import (
    CryptoBackend,
    get_crypto_backend,
    available_backends,
    set_encryption_key,
    set_sm2_keypair,
)
from fastapi_sm.login import login

__all__ = [
    "__version__",
    "BasePasswordHasher",
    "SM3PasswordHasher",
    "AbstractUser",
    "User",
    "Base",
    "SQLALCHEMY_AVAILABLE",
    "TORTOISE_AVAILABLE",
    "CryptoBackend",
    "get_crypto_backend",
    "available_backends",
    "set_encryption_key",
    "set_sm2_keypair",
    "login",
]
