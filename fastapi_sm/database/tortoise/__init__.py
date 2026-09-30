# -*- coding: utf-8 -*-
"""Tortoise-ORM 适配子包（可选）。

仅当环境中已安装 ``tortoise-orm`` 时才导出 ``User``；未安装则该子包为空
（User 为 None），不会抛出 ImportError，从而把 ORM 变成可选项。
"""

User = None
EncryptedString = None

try:
    from fastapi_sm.database.tortoise.fields import (  # noqa: F811
        EncryptedString,
    )
    from fastapi_sm.database.tortoise.models import User  # noqa: F811
    TORTOISE_AVAILABLE = True
except ImportError:  # pragma: no cover
    TORTOISE_AVAILABLE = False

__all__ = ["User", "EncryptedString", "TORTOISE_AVAILABLE"]
