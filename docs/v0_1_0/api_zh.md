# fastapi-sm API 文档（中文）

> 版本：v0.1
> 本文档覆盖 `fastapi_sm` 的公开 API：统一国密后端、口令哈希、登录校验、多 ORM 透明加密字段。

---

## 1. 统一加解密后端 `fastapi_sm.backends`

后端为可选项：未安装对应底层库时该后端不会被注册，不会抛 `ImportError`。
默认按 `("pysmx", "gmssl_pyx")` 顺序探测，非对称优先 pysmx。

### 1.1 `get_crypto_backend(name=None) -> CryptoBackend`

返回已初始化的统一加解密后端实例。

| 项 | 说明 |
|----|------|
| 输入 | `name`（`str`，可选）：指定后端名 `"pysmx"` 或 `"gmssl_pyx"`；省略则按默认顺序返回第一个可用后端 |
| 输出 | `CryptoBackend` 实例 |
| 异常 | `BackendNotAvailable`：无任何可用后端，或指定的 `name` 未安装/未知 |

```python
from fastapi_sm.backends import get_crypto_backend
backend = get_crypto_backend()          # 首个可用后端
backend = get_crypto_backend("pysmx")   # 显式指定
```

### 1.2 `available_backends() -> list[str]`

返回当前已注册（可用）的后端名称列表。

| 项 | 说明 |
|----|------|
| 输入 | 无 |
| 输出 | `list[str]`，如 `['pysmx', 'gmssl_pyx']`（取决于安装） |

### 1.3 `CryptoBackend`（统一接口）

所有后端实现的统一接口（抽象基类，位于 `fastapi_sm.backends.base`）。密钥一律以原始 `bytes` 传递：SM2 私钥 32 字节、SM4 密钥 16 字节、SM2 公钥为各后端约定的原始公钥字节（不同后端之间不保证可互验）。

| 方法 | 输入 | 输出 | 功能 |
|------|------|------|------|
| `sm3_hash(data: bytes) -> bytes` | 待哈希字节 | 32 字节摘要 | SM3 哈希 |
| `hmac_sm3(key: bytes, msg: bytes) -> bytes` | 密钥、消息字节 | 32 字节 HMAC | 基于本后端 `sm3_hash` 的 HMAC-SM3 |
| `sm2_generate_keypair() -> (bytes, bytes)` | 无 | `(private_key, public_key)` | 生成 SM2 密钥对 |
| `sm2_sign(msg, private_key, public_key, uid) -> bytes` | 消息、私钥、公钥、uid（`bytes`） | 签名字节（DER `rs`） | SM2 签名（类式 API） |
| `sm2_verify(msg, signature, public_key, uid) -> bool` | 消息、签名、公钥、uid | `True/False` | SM2 验签 |
| `sm2_encrypt(public_key, plaintext) -> bytes` | 公钥、明文 | 密文 | SM2 公钥加密 |
| `sm2_decrypt(private_key, ciphertext) -> bytes` | 私钥、密文 | 明文 | SM2 私钥解密 |
| `sm4_encrypt(key, plaintext) -> bytes` | 16 字节密钥、明文 | `iv ‖ 密文`（随机 IV 已拼接） | SM4-CBC 对称加密 |
| `sm4_decrypt(key, ciphertext) -> bytes` | 16 字节密钥、`iv ‖ 密文` | 明文 | SM4-CBC 对称解密 |

说明：
- `sm4_encrypt` 每次生成随机 IV，结果自带恢复所需随机量，解密无需额外传参。
- 两后端 SM4 密文互相兼容；SM2 签名因编码差异跨后端不保证互验。

### 1.4 具体后端类

- `PysmxBackend`（`name="pysmx"`）：基于 `snowland-smx`（pysmx）的实现。
- `GmsslPyxBackend`（`name="gmssl_pyx"`）：基于 `gmssl-pyx`（libgmssl 原生绑定）的实现。

二者均实现 `CryptoBackend` 全部方法，可经 `get_crypto_backend("pysmx"/"gmssl_pyx")` 获取实例。

### 1.5 全局密钥配置（通用工具）

| 函数 | 输入 | 输出 | 功能 |
|------|------|------|------|
| `set_encryption_key(key)` | SM4 密钥（`str` 按 utf-8 或 `bytes`，须 16 字节） | `None` | 设置全局默认 SM4 密钥 |
| `set_sm2_keypair(private_key, public_key)` | 私钥、公钥字节 | `None` | 设置全局默认 SM2 密钥对 |
| `get_default_sm4_key() -> bytes` | 无 | 当前默认 SM4 密钥 | 读取默认 SM4 密钥 |
| `get_default_sm2_keypair() -> (bytes, bytes)` | 无 | 当前默认 SM2 密钥对 | 读取默认 SM2 密钥对 |

> 注意：`EncryptedString` 字段**不**使用这些全局默认密钥，密钥必须由字段自身持有（见 §4）。这些函数仅作通用工具保留。

### 1.6 `BackendNotAvailable`

异常类。当没有任何（或请求的）加解密后端可导入时抛出。

---

## 2. 口令哈希 `fastapi_sm.hasher`

### 2.1 `BasePasswordHasher`（抽象基类）

定义口令哈希器契约，子类须实现：`salt()`、`encode()`、`verify()`、`must_update()`、`safe_summary()`。

### 2.2 `SM3PasswordHasher(iterations=100_000)`

基于 SM3 + PBKDF2-HMAC-SM3 的口令哈希器（Django 风格四段编码 `algorithm$iterations$salt$hash`）。

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `iterations` | `int` | `100_000` | PBKDF2 迭代次数，可按硬件性能调整 |

常量：`SM3_DIGEST_SIZE=32`、`DEFAULT_SALT_BYTES=16`、`DEFAULT_ITERATIONS=100_000`。

| 方法 | 输入 | 输出 | 功能 |
|------|------|------|------|
| `salt() -> str` | 无 | 随机 salt（hex 字符串） | 生成随机盐 |
| `encode(password: str, salt: str = None) -> str` | 明文口令、可选 salt | 四段哈希字符串 | 哈希明文口令 |
| `verify(password: str, encoded: str) -> bool` | 明文口令、已存哈希 | `True/False` | 校验口令 |
| `must_update(encoded: str) -> bool` | 已存哈希 | `True/False` | 是否需要重哈希（算法变更或迭代次数偏低） |
| `safe_summary(encoded: str) -> dict` | 已存哈希 | 脱敏摘要字典 | 日志/调试用，salt 与 hash 均脱敏 |

---

## 3. 登录校验 `fastapi_sm.login`

### 3.1 `login(get_user, username, password) -> AbstractUser | None`

与存储实现解耦的登录校验：只需一个「按用户名取用户」的函数。

| 参数 | 类型 | 说明 |
|------|------|------|
| `get_user` | `Callable[[str], Optional[AbstractUser]]` | 按用户名取用户，取不到返回 `None` |
| `username` | `str` | 登录用户名 |
| `password` | `str` | 明文口令 |

| 项 | 说明 |
|----|------|
| 输出 | 成功返回用户对象（`AbstractUser` 子类），失败（未知用户或口令错误）返回 `None` |

```python
from fastapi_sm.database import User
from fastapi_sm.login import login

admin = User(username="admin"); admin.set_password("secret")
repo = {"admin": admin}
user = login(lambda n: repo.get(n), "admin", "secret")  # -> admin 或 None
```

---

## 4. 多 ORM 透明加密字段 `fastapi_sm.database`

ORM 适配层为可选项：未安装对应依赖时对应导出置为 `None`，不抛异常。

### 4.1 `AbstractUser`（抽象契约）

与具体 ORM 解耦的用户契约，约定 `username` / `password` 两个属性，并提供：

| 方法 | 输入 | 输出 | 功能 |
|------|------|------|------|
| `set_password(raw_password: str) -> None` | 明文口令 | 无（写入 `self.password` 哈希） | 哈希并存储口令 |
| `check_password(raw_password: str) -> bool` | 明文口令 | `True/False` | 校验口令（空口令直接返回 `False`） |

### 4.2 具体模型与基类

- `User`：SQLAlchemy 或 Tortoise 的具体用户模型（由已安装的 ORM 决定）。
- `Base`：SQLAlchemy 声明基类（仅 SQLAlchemy 可用时导出，否则为 `None`）。

### 4.3 `EncryptedString`（SQLAlchemy 字段）

位置：`fastapi_sm.database.sqlalchemy.fields.EncryptedString`（经 `fastapi_sm.database` 导出）。
继承 `sqlalchemy.types.String`，应用层按普通字符串读写，存储层自动加密/解密。

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `key` | `bytes`（对称）或 `(bytes, bytes)` 元组（非对称） | 必填 | 对称=SM4 密钥（16 字节）；非对称=SM2 `(private, public)` 密钥对。**不从全局默认取用** |
| `mode` | `str` | `"symmetric"` | `"symmetric"`（SM4）或 `"asymmetric"`（SM2） |
| `length` | `int` | `512` | 列长度，须足够容纳 base64 密文 |

| 方法 | 方向 | 功能 |
|------|------|------|
| `process_bind_param(value, dialect)` | 应用层→库 | 明文（str）→ 密文字符串（str，base64） |
| `process_result_value(value, dialect)` | 库→应用层 | 密文字符串 → 明文（str） |

```python
from fastapi_sm.database.sqlalchemy.fields import EncryptedString
secret = mapped_column(EncryptedString(key=b"0123456789abcdef", length=512))
# 非对称：
# EncryptedString(key=(private_key, public_key), mode="asymmetric", length=512)
```

### 4.4 `TortoiseEncryptedString`（Tortoise 字段）

位置：`fastapi_sm.database.tortoise.fields.EncryptedString`（经 `fastapi_sm.database` 以 `TortoiseEncryptedString` 导出）。
继承 `tortoise.fields.CharField`，行为同 §4.3。

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `key` | 同 §4.3 | 必填 | 对称 SM4 密钥或 SM2 密钥对 |
| `mode` | `str` | `"symmetric"` | 同 §4.3 |
| `max_length` | `int` | `512` | 列长度（CharField 必填） |

| 方法 | 方向 | 功能 |
|------|------|------|
| `to_db_value(value, instance)` | 应用层→库 | 明文 → 密文（base64 字符串） |
| `to_python_value(value)` | 库→应用层 | 密文 → 明文 |

```python
from fastapi_sm.database.tortoise.fields import EncryptedString
secret = EncryptedString(key=b"0123456789abcdef", max_length=512)
```

### 4.5 可用性与工具

| 名称 | 类型 | 说明 |
|------|------|------|
| `SQLALCHEMY_AVAILABLE` | `bool` | SQLAlchemy 适配是否可用 |
| `TORTOISE_AVAILABLE` | `bool` | Tortoise 适配是否可用 |
| `set_encryption_key` | 函数 | 同 §1.5（通用工具，由 `fastapi_sm.backends` 重新导出） |
