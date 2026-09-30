# -*- coding: utf-8 -*-
"""SQLAlchemy 适配子包（可选）。

仅当环境中已安装 ``sqlalchemy`` 时才导出 ``Base`` / ``User``；未安装则该
子包为空（Base / User 为 None），不会抛出 ImportError，从而把 ORM 变成可选项。
"""

Base = None
User = None

try:
    from fastapi_sm.backends import set_encryption_key  # noqa: F811
    from fastapi_sm.database.sqlalchemy.models import Base, User  # noqa: F811
    from fastapi_sm.database.sqlalchemy.fields import EncryptedString
    SQLALCHEMY_AVAILABLE = True
except ImportError:  # pragma: no cover
    EncryptedString = None
    set_encryption_key = None
    SQLALCHEMY_AVAILABLE = False

__all__ = [
    "Base",
    "User",
    "EncryptedString",
    "set_encryption_key",
    "SQLALCHEMY_AVAILABLE",
]
