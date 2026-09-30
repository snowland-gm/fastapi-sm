# -*- coding: utf-8 -*-
"""SQLAlchemy 适配：基于 fastapi_sm.database.base.AbstractUser 的用户模型。"""

from abc import ABCMeta

from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastapi_sm.database.base import AbstractUser


class Base(DeclarativeBase):
    """SQLAlchemy 声明基类，供本适配层所有模型继承。"""


class _DeclarativeABCMeta(ABCMeta, type(Base)):
    """合并元类：同时兼容 SQLAlchemy 声明映射与标准 ABC 抽象能力。"""


class User(AbstractUser, Base, metaclass=_DeclarativeABCMeta):
    """SQLAlchemy 用户模型，复用 AbstractUser 的口令哈希逻辑。"""

    __tablename__ = "users"

    #: 用户名（主键）
    username: Mapped[str] = mapped_column(String(150), primary_key=True)
    #: 口令哈希（非明文）
    password: Mapped[str] = mapped_column(String(255))
