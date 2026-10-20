# fastapi-sm API Reference (English)

> Version: v0.1
> This document covers the public API of `fastapi_sm`: the unified national-crypto
> backend, password hashing, login verification, and transparent encrypted fields
> for multiple ORMs.

---

## 1. Unified crypto backend `fastapi_sm.backends`

Backends are optional: if a backend's underlying library is not installed it is
simply not registered and no `ImportError` is raised. By default backends are
probed in `("pysmx", "gmssl_pyx")` order (pysmx preferred for asymmetric).

### 1.1 `get_crypto_backend(name=None) -> CryptoBackend`

Returns an initialized unified crypto backend instance.

| Item | Description |
|------|-------------|
| Input | `name` (`str`, optional): backend name `"pysmx"` or `"gmssl_pyx"`; if omitted, the first available backend in default order is returned |
| Output | `CryptoBackend` instance |
| Raises | `BackendNotAvailable`: no backend available, or the requested `name` is unknown/not installed |

```python
from fastapi_sm.backends import get_crypto_backend
backend = get_crypto_backend()          # first available backend
backend = get_crypto_backend("pysmx")   # explicit
```

### 1.2 `available_backends() -> list[str]`

Returns the list of currently registered (available) backend names.

| Item | Description |
|------|-------------|
| Input | none |
| Output | `list[str]`, e.g. `['pysmx', 'gmssl_pyx']` (depends on what is installed) |

### 1.3 `CryptoBackend` (unified interface)

The unified interface implemented by every backend (abstract base class in
`fastapi_sm.backends.base`). Keys are always raw `bytes`: SM2 private key is
32 bytes, SM4 key is 16 bytes, SM2 public key is the backend-specific raw public
key bytes (not guaranteed cross-backend verifiable).

| Method | Input | Output | Function |
|--------|-------|--------|----------|
| `sm3_hash(data: bytes) -> bytes` | bytes to hash | 32-byte digest | SM3 hash |
| `hmac_sm3(key: bytes, msg: bytes) -> bytes` | key, message bytes | 32-byte HMAC | HMAC-SM3 based on this backend's `sm3_hash` |
| `sm2_generate_keypair() -> (bytes, bytes)` | none | `(private_key, public_key)` | generate SM2 keypair |
| `sm2_sign(msg, private_key, public_key, uid) -> bytes` | msg, priv, pub, uid (`bytes`) | signature bytes (DER `rs`) | SM2 sign (class-based API) |
| `sm2_verify(msg, signature, public_key, uid) -> bool` | msg, sig, pub, uid | `True/False` | SM2 verify |
| `sm2_encrypt(public_key, plaintext) -> bytes` | public key, plaintext | ciphertext | SM2 public-key encrypt |
| `sm2_decrypt(private_key, ciphertext) -> bytes` | private key, ciphertext | plaintext | SM2 private-key decrypt |
| `sm4_encrypt(key, plaintext) -> bytes` | 16-byte key, plaintext | `iv ‖ ciphertext` (random IV prepended) | SM4-CBC symmetric encrypt |
| `sm4_decrypt(key, ciphertext) -> bytes` | 16-byte key, `iv ‖ ciphertext` | plaintext | SM4-CBC symmetric decrypt |

Notes:
- `sm4_encrypt` generates a random IV each call; the result carries everything
  needed to recover the plaintext, so no extra argument is needed for decryption.
- SM4 ciphertext is cross-backend compatible; SM2 signatures are NOT guaranteed
  cross-backend verifiable due to encoding differences.

### 1.4 Concrete backend classes

- `PysmxBackend` (`name="pysmx"`): implementation based on `snowland-smx` (pysmx).
- `GmsslPyxBackend` (`name="gmssl_pyx"`): implementation based on `gmssl-pyx`
  (libgmssl native binding).

Both implement the full `CryptoBackend` interface and are obtained via
`get_crypto_backend("pysmx"/"gmssl_pyx")`.

### 1.5 Global key configuration (general helpers)

| Function | Input | Output | Function |
|----------|-------|--------|----------|
| `set_encryption_key(key)` | SM4 key (`str` utf-8 or `bytes`, must be 16 bytes) | `None` | set global default SM4 key |
| `set_sm2_keypair(private_key, public_key)` | private, public bytes | `None` | set global default SM2 keypair |
| `get_default_sm4_key() -> bytes` | none | current default SM4 key | read default SM4 key |
| `get_default_sm2_keypair() -> (bytes, bytes)` | none | current default SM2 keypair | read default SM2 keypair |

> Note: the `EncryptedString` field does NOT use these global defaults — its key
> must be owned by the field itself (see §4). These functions are kept only as
> general-purpose helpers.

### 1.6 `BackendNotAvailable`

Exception raised when no (or the requested) crypto backend can be imported.

---

## 2. Password hashing `fastapi_sm.hasher`

### 2.1 `BasePasswordHasher` (abstract base class)

Defines the password-hasher contract. Subclasses must implement `salt()`,
`encode()`, `verify()`, `must_update()`, and `safe_summary()`.

### 2.2 `SM3PasswordHasher(iterations=100_000)`

Password hasher based on SM3 + PBKDF2-HMAC-SM3 (Django-style four-segment
encoding `algorithm$iterations$salt$hash`).

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `iterations` | `int` | `100_000` | PBKDF2 iteration count, tune to hardware |

Constants: `SM3_DIGEST_SIZE=32`, `DEFAULT_SALT_BYTES=16`, `DEFAULT_ITERATIONS=100_000`.

| Method | Input | Output | Function |
|--------|-------|--------|----------|
| `salt() -> str` | none | random salt (hex string) | generate random salt |
| `encode(password: str, salt: str = None) -> str` | plaintext, optional salt | four-segment hash string | hash a plaintext password |
| `verify(password: str, encoded: str) -> bool` | plaintext, stored hash | `True/False` | verify a password |
| `must_update(encoded: str) -> bool` | stored hash | `True/False` | whether re-hashing is needed (algorithm change or low iteration count) |
| `safe_summary(encoded: str) -> dict` | stored hash | masked summary dict | for logs/debug; salt and hash are masked |

---

## 3. Login verification `fastapi_sm.login`

### 3.1 `login(get_user, username, password) -> AbstractUser | None`

Storage-decoupled login verification: only needs a "get user by name" function.

| Param | Type | Description |
|-------|------|-------------|
| `get_user` | `Callable[[str], Optional[AbstractUser]]` | fetch user by name; return `None` if not found |
| `username` | `str` | login username |
| `password` | `str` | plaintext password |

| Item | Description |
|------|-------------|
| Output | the user object on success, `None` on failure (unknown user or wrong password) |

```python
from fastapi_sm.database import User
from fastapi_sm.login import login

admin = User(username="admin"); admin.set_password("secret")
repo = {"admin": admin}
user = login(lambda n: repo.get(n), "admin", "secret")  # -> admin or None
```

---

## 4. Transparent encrypted fields for multiple ORMs `fastapi_sm.database`

ORM adapters are optional: if a dependency is missing the corresponding export is
set to `None` instead of raising.

### 4.1 `AbstractUser` (abstract contract)

ORM-agnostic user contract declaring `username` / `password` and providing:

| Method | Input | Output | Function |
|--------|-------|--------|----------|
| `set_password(raw_password: str) -> None` | plaintext | none (writes hashed `self.password`) | hash and store password |
| `check_password(raw_password: str) -> bool` | plaintext | `True/False` | verify password (empty password returns `False`) |

### 4.2 Concrete model and base

- `User`: concrete user model (SQLAlchemy or Tortoise, depending on what is installed).
- `Base`: SQLAlchemy declarative base (exported only when SQLAlchemy is available, else `None`).

### 4.3 `EncryptedString` (SQLAlchemy field)

Location: `fastapi_sm.database.sqlalchemy.fields.EncryptedString` (re-exported via
`fastapi_sm.database`). Subclasses `sqlalchemy.types.String`; plaintext at the app
layer, automatic encrypt/decrypt at storage layer.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `key` | `bytes` (symmetric) or `(bytes, bytes)` tuple (asymmetric) | required | symmetric = SM4 key (16 bytes); asymmetric = SM2 `(private, public)` keypair. **Not taken from global defaults** |
| `mode` | `str` | `"symmetric"` | `"symmetric"` (SM4) or `"asymmetric"` (SM2) |
| `length` | `int` | `512` | column length, must hold the base64 ciphertext |

| Method | Direction | Function |
|--------|-----------|----------|
| `process_bind_param(value, dialect)` | app → DB | plaintext (str) → ciphertext string (str, base64) |
| `process_result_value(value, dialect)` | DB → app | ciphertext string → plaintext (str) |

```python
from fastapi_sm.database.sqlalchemy.fields import EncryptedString
secret = mapped_column(EncryptedString(key=b"0123456789abcdef", length=512))
# asymmetric:
# EncryptedString(key=(private_key, public_key), mode="asymmetric", length=512)
```

### 4.4 `TortoiseEncryptedString` (Tortoise field)

Location: `fastapi_sm.database.tortoise.fields.EncryptedString` (re-exported via
`fastapi_sm.database` as `TortoiseEncryptedString`). Subclasses
`tortoise.fields.CharField`; same behavior as §4.3.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `key` | same as §4.3 | required | SM4 key or SM2 keypair |
| `mode` | `str` | `"symmetric"` | same as §4.3 |
| `max_length` | `int` | `512` | column length (required by CharField) |

| Method | Direction | Function |
|--------|-----------|----------|
| `to_db_value(value, instance)` | app → DB | plaintext → ciphertext (base64 string) |
| `to_python_value(value)` | DB → app | ciphertext → plaintext |

```python
from fastapi_sm.database.tortoise.fields import EncryptedString
secret = EncryptedString(key=b"0123456789abcdef", max_length=512)
```

### 4.5 Availability and helpers

| Name | Type | Description |
|------|------|-------------|
| `SQLALCHEMY_AVAILABLE` | `bool` | whether the SQLAlchemy adapter is available |
| `TORTOISE_AVAILABLE` | `bool` | whether the Tortoise adapter is available |
| `set_encryption_key` | function | same as §1.5 (general helper, re-exported from `fastapi_sm.backends`) |
