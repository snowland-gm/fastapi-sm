# fastapi-sm

FastAPI 友好的国密（SM2/SM3/SM4）工具库，封装 snowland-smx 的底层密码学原语，
提供**统一加解密后端**、**国密口令哈希**与**多 ORM 透明加密字段**，供登录鉴权、
敏感字段存储等场景直接复用。

> 核心理念：底层密码学由两个可选后端 `snowland-smx`（pysmx）与 `gmssl-pyx`
> 之一提供；本库在其之上做**统一接口封装**，业务代码只依赖 `fastapi_sm.backends`
> 暴露的稳定 API，不关心具体后端。

## 能力一览

| 模块 | 国密算法 | 用途 |
|------|----------|------|
| `backends` | SM2 / SM3 / SM4 | 统一加解密后端（SM3 哈希、SM2 签名/验签/加解密、SM4 对称加解密） |
| `hasher` | SM3 + PBKDF2 | 口令哈希（Django 风格 `algorithm$iterations$salt$hash`），杜绝明文 |
| `database` | SM4-CBC / SM2 | 多 ORM 透明加密字段（应用层无感，存储层密文） |
| `login` | — | 解耦存储的登录校验（只需「按用户名取用户」函数） |

## 安装

```bash
pip install fastapi-sm
```

后端为可选项，二者至少安装其一（非对称优先使用 pysmx）：

```bash
# 任选其一
pip install fastapi-sm[pysmx]   # 对应 pysmx 后端（非对称优先）
pip install fastapi-sm[gmssl]   # 对应 gmssl_pyx 后端
# 或直接装拆分文件：
pip install -r requirements/backend-pysmx.txt
pip install -r requirements/backend-gmssl.txt
```

ORM 适配层按需安装（不装则对应子包自动置为 `None`，不会报错）：

```bash
pip install fastapi-sm[sqlalchemy]   # SQLAlchemy 适配
pip install fastapi-sm[tortoise]     # Tortoise-ORM 适配（异步）
# 或：
pip install -r requirements/orm-sqlalchemy.txt
pip install -r requirements/orm-tortoise.txt
```

依赖拆分以 `pyproject.toml` 为准，详见 `requirements/` 下按能力拆分的文件。
必装：`fastapi` + `snowland-jwt`。

## 统一加解密后端

```python
from fastapi_sm.backends import (
    get_crypto_backend,
    available_backends,
    set_encryption_key,
    set_sm2_keypair,
)

print(available_backends())          # ['pysmx', 'gmssl_pyx']（按安装情况）
backend = get_crypto_backend()       # 返回首个可用后端实例

# SM3 哈希
digest = backend.sm3_hash(b"hello")

# SM4 对称加解密（密钥 16 字节）
key = b"0123456789abcdef"
cipher = backend.sm4_encrypt(key, b"plain")
plain = backend.sm4_decrypt(key, cipher)

# SM2 非对称加解密（密钥对为 (private, public) 字节）
priv, pub = backend.sm2_generate_keypair()
cipher = backend.sm2_encrypt(pub, b"plain")
plain = backend.sm2_decrypt(priv, cipher)

# SM2 签名 / 验签（类式 API）
uid = b"1234567812345678"
sig = backend.sm2_sign(b"msg", priv, pub, uid)
ok = backend.sm2_verify(b"msg", sig, pub, uid)
```

也可指定后端：

```python
backend = get_crypto_backend("pysmx")
```

## 国密口令哈希

```python
from fastapi_sm.hasher import SM3PasswordHasher

hasher = SM3PasswordHasher()
encoded = hasher.encode("secret123")   # sm3_pbkdf2$100000$<salt>$<hash>
assert hasher.verify("secret123", encoded)
```

## 多 ORM 透明加密字段

加密字段**应用层按普通字符串读写，存储层自动为密文**；密钥由字段自身持有，
不回退全局默认（加密/签名密钥不同且需轮换）。

对称（SM4，密钥 16 字节）：

```python
from fastapi_sm.database.sqlalchemy.types import EncryptedString

class Account(Base):
    __tablename__ = "accounts"
    username = mapped_column(String(150), primary_key=True)
    secret = mapped_column(EncryptedString(key=b"0123456789abcdef", length=512))
```

非对称（SM2，密钥对 `(private, public)`）：

```python
secret = mapped_column(
    EncryptedString(key=(private_key, public_key), mode="asymmetric", length=512)
)
```

Tortoise-ORM 用法完全一致：

```python
from fastapi_sm.database.tortoise.fields import EncryptedString

class Account(models.Model):
    username = fields.CharField(max_length=150, pk=True)
    secret = EncryptedString(key=b"0123456789abcdef", max_length=512)
```

用户模型（提供 `set_password` / `check_password`，复用上面的口令哈希）：

```python
from fastapi_sm.database import User   # SQLAlchemy；Tortoise 用 database.tortoise.User

# 透明加密字段同样可挂到任意列，由使用方按业务决定，库本身不预设任何业务字段。
```

## 登录校验（解耦存储）

```python
from fastapi_sm.database import User
from fastapi_sm.login import login

admin = User(username="admin")
admin.set_password("secret")

def get_user(name: str):
    return admin if name == "admin" else None

user = login(get_user, "admin", "secret")   # 成功返回 user，失败返回 None
```

## 设计说明

- **后端可插拔**：`pysmx` 与 `gmssl_pyx` 实现同一套 `CryptoBackend` 接口，默认
  按 `("pysmx", "gmssl_pyx")` 探测。SM4 密文跨后端兼容；SM2 签名因编码差异
  跨后端不保证互验（与 snowland-jwt 一致）。
- **ORM 可插拔**：`sqlalchemy` / `tortoise` 子包按需探测，缺依赖不影响导入。
- **密钥由调用方持有**：`EncryptedString` 的 `key` 必填，支持按列轮换，
  不依赖全局默认密钥（仅 `backends.set_encryption_key` 作为通用工具保留）。

## 依赖

以 `pyproject.toml` 为准。必装：`fastapi` + `snowland-jwt`；运行期需在国密后端
（`snowland-smx` 或 `gmssl-pyx`）二选一；ORM 适配按需。
