# -*- coding: utf-8 -*-
"""登录函数（fastapi_sm 模块内部子模块）。

演示如何使用 fastapi_sm.database 的抽象用户与 fastapi_sm.hasher 的国密哈希
完成基于 SM3 的登录校验。登录只需一个「按用户名取出用户」的获取函数，不绑定
任何存储实现。
"""

from typing import Callable, Optional

from fastapi_sm.database import AbstractUser

#: 按用户名取用户，取不到返回 None
UserGetter = Callable[[str], Optional[AbstractUser]]


def login(
    get_user: UserGetter, username: str, password: str
) -> Optional[AbstractUser]:
    """校验用户名 / 口令，成功返回用户对象，失败返回 None。

    :param get_user: 按用户名取出用户的函数（可指向 ORM 查询等）
    :param username: 登录用户名
    :param password: 明文口令
    """
    user = get_user(username)
    if user is None:
        return None
    if user.check_password(password):
        return user
    return None


if __name__ == "__main__":
    from fastapi_sm.database import User

    # 用最简单的字典模拟存储，演示 login 不依赖具体存储实现
    repo = {}

    def get_user(name: str) -> Optional[AbstractUser]:
        return repo.get(name)

    admin = User(username="admin")
    admin.set_password("secret")  # 存储的是 sm3_pbkdf2$... 哈希
    repo["admin"] = admin

    ok_user = login(get_user, "admin", "secret")
    bad_pwd = login(get_user, "admin", "wrong")
    unknown = login(get_user, "nobody", "x")

    print("登录(正确口令):", ok_user.username if ok_user else None)
    print("登录(错误口令):", bad_pwd.username if bad_pwd else None)
    print("登录(未知用户):", unknown.username if unknown else None)
    print("存储的哈希:", admin.password)
