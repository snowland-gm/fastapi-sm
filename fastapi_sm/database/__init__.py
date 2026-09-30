# -*- coding: utf-8 -*-
"""database 子模块：多 ORM（可选）用户模型与抽象用户契约。

- ``base``：ORM 无关的 ``AbstractUser`` 契约（含 set_password / check_password）
- ``sqlalchemy``：SQLAlchemy 适配（Base + User + EncryptedString），可选，需装 ``sqlalchemy``
- ``tortoise``：Tortoise-ORM 适配（User），可选，需装 ``tortoise-orm``

ORM 适配层为**可选项**：未安装对应依赖的子包不会报错，只会将其导出置为
``None``。默认导出的 ``Base`` / ``User`` 按 ``sqlalchemy → tortoise`` 的优先级
取第一个可用的 ORM；若两个都没装，则只保留 ORM 无关的 ``AbstractUser`` 契约。
"""

from fastapi_sm.database.base import AbstractUser
from fastapi_sm.database.sqlalchemy import (
    Base,
    User,
    EncryptedString,
    set_encryption_key,
    SQLALCHEMY_AVAILABLE,
)
from fastapi_sm.database.tortoise import (
    EncryptedString as TortoiseEncryptedString,
    TORTOISE_AVAILABLE,
)

__all__ = [
    "AbstractUser",
    "Base",
    "User",
    "EncryptedString",
    "TortoiseEncryptedString",
    "set_encryption_key",
    "SQLALCHEMY_AVAILABLE",
    "TORTOISE_AVAILABLE",
]
