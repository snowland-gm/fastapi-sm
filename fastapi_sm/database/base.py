# -*- coding: utf-8 -*-
"""用户抽象契约（与具体 ORM 解耦）。

``AbstractUser`` 只约定 ``username`` / ``password`` 两个属性，并基于
fastapi_sm.hasher 提供 ``set_password`` / ``check_password``。它本身不绑定任何
ORM，具体持久化映射由各适配层（sqlalchemy / tortoise）负责，从而支持多 ORM。
"""

from abc import ABC

from fastapi_sm.hasher import SM3PasswordHasher


class AbstractUser(ABC):
    """抽象用户契约，具体 ORM 模型须提供 ``username`` / ``password`` 字段。

    ``password`` 存储哈希后的口令，绝不明文存储。
    """

    #: 用户名（各 ORM 适配层映射为主键列）
    username: str
    #: 口令哈希（由 set_password 写入），非明文
    password: str

    #: 复用同一个国密哈希器实例
    _hasher = SM3PasswordHasher()

    def set_password(self, raw_password: str) -> None:
        """将明文口令哈希后写入 ``self.password``。"""
        self.password = self._hasher.encode(raw_password)

    def check_password(self, raw_password: str) -> bool:
        """校验明文口令是否与已存储哈希匹配。"""
        if not self.password:
            return False
        return self._hasher.verify(raw_password, self.password)

    def __repr__(self) -> str:  # pragma: no cover
        return f"{type(self).__name__}(username={getattr(self, 'username', None)!r})"
