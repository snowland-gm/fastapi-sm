# -*- coding: utf-8 -*-
"""Tortoise-ORM 适配：基于 fastapi_sm.database.base.AbstractUser 的用户模型。"""

from abc import ABCMeta

from tortoise import fields, models

from fastapi_sm.database.base import AbstractUser


class _TortoiseABCMeta(ABCMeta, type(models.Model)):
    """合并元类：同时兼容 Tortoise 模型元类与标准 ABC 抽象能力。"""


class User(AbstractUser, models.Model, metaclass=_TortoiseABCMeta):
    """Tortoise-ORM 用户模型，复用 AbstractUser 的口令哈希逻辑。"""

    #: 用户名（主键）
    username = fields.CharField(max_length=150, pk=True)
    #: 口令哈希（非明文）
    password = fields.CharField(max_length=255)
