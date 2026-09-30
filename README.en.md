# fastapi-sm

A FastAPI-friendly library for Chinese national cryptography (SM2/SM3/SM4). It
wraps the low-level primitives of `snowland-smx` and provides a **unified crypto
backend**, **national-standard password hashing**, and **transparent encrypted
fields for multiple ORMs**, ready to reuse in login/auth and sensitive-field
storage scenarios.

> Core idea: the underlying cryptography is provided by one of two optional
> backends — `snowland-smx` (pysmx) or `gmssl-pyx`. This library adds a
> **unified interface** on top of them: business code only depends on the stable
> API exposed by `fastapi_sm.backends` and never cares about the concrete backend.

## Feature overview

| Module | Algorithm | Purpose |
|--------|-----------|---------|
| `backends` | SM2 / SM3 / SM4 | Unified crypto backend (SM3 hash, SM2 sign/verify/encrypt/decrypt, SM4 symmetric encrypt/decrypt) |
| `hasher` | SM3 + PBKDF2 | Password hashing (Django-style `algorithm$iterations$salt$hash`), no plaintext |
| `database` | SM4-CBC / SM2 | Transparent encrypted fields for multiple ORMs (plaintext at app layer, ciphertext at storage layer) |
| `login` | — | Storage-decoupled login verification (only needs a "get user by name" function) |

## Installation

```bash
pip install fastapi-sm
```

Backends are optional; install at least one (pysmx is preferred for asymmetric):

```bash
# pick one
pip install fastapi-sm[pysmx]   # pysmx backend (preferred for asymmetric)
pip install fastapi-sm[gmssl]   # gmssl_pyx backend
# or install the requirement files directly:
pip install -r requirements/backend-pysmx.txt
pip install -r requirements/backend-gmssl.txt
```

ORM adapters are optional (missing ones are set to `None` automatically, no error):

```bash
pip install fastapi-sm[sqlalchemy]   # SQLAlchemy adapter
pip install fastapi-sm[tortoise]     # Tortoise-ORM adapter (async)
# or:
pip install -r requirements/orm-sqlalchemy.txt
pip install -r requirements/orm-tortoise.txt
```

See `pyproject.toml` for the authoritative dependency split, and `requirements/`
for the per-feature files. Required deps: `fastapi` + `snowland-jwt`.

## Unified crypto backend

```python
from fastapi_sm.backends import (
    get_crypto_backend,
    available_backends,
    set_encryption_key,
    set_sm2_keypair,
)

print(available_backends())          # ['pysmx', 'gmssl_pyx'] (depends on install)
backend = get_crypto_backend()       # first available backend instance

# SM3 hash
digest = backend.sm3_hash(b"hello")

# SM4 symmetric encrypt/decrypt (16-byte key)
key = b"0123456789abcdef"
cipher = backend.sm4_encrypt(key, b"plain")
plain = backend.sm4_decrypt(key, cipher)

# SM2 asymmetric encrypt/decrypt (keypair is (private, public) bytes)
priv, pub = backend.sm2_generate_keypair()
cipher = backend.sm2_encrypt(pub, b"plain")
plain = backend.sm2_decrypt(priv, cipher)

# SM2 sign / verify (class-based API)
uid = b"1234567812345678"
sig = backend.sm2_sign(b"msg", priv, pub, uid)
ok = backend.sm2_verify(b"msg", sig, pub, uid)
```

You can also pick a backend explicitly:

```python
backend = get_crypto_backend("pysmx")
```

## National-standard password hashing

```python
from fastapi_sm.hasher import SM3PasswordHasher

hasher = SM3PasswordHasher()
encoded = hasher.encode("secret123")   # sm3_pbkdf2$100000$<salt>$<hash>
assert hasher.verify("secret123", encoded)
```

## Transparent encrypted fields for multiple ORMs

Encrypted fields are **plain strings at the app layer and ciphertext at the
storage layer**. The key is owned by the field itself — it never falls back to a
global default (encryption keys and signing keys differ and must be rotated).

Symmetric (SM4, 16-byte key):

```python
from fastapi_sm.database.sqlalchemy.types import EncryptedString

class Account(Base):
    __tablename__ = "accounts"
    username = mapped_column(String(150), primary_key=True)
    secret = mapped_column(EncryptedString(key=b"0123456789abcdef", length=512))
```

Asymmetric (SM2, keypair `(private, public)`):

```python
secret = mapped_column(
    EncryptedString(key=(private_key, public_key), mode="asymmetric", length=512)
)
```

Tortoise-ORM usage is identical:

```python
from fastapi_sm.database.tortoise.fields import EncryptedString

class Account(models.Model):
    username = fields.CharField(max_length=150, pk=True)
    secret = EncryptedString(key=b"0123456789abcdef", max_length=512)
```

User model (provides `set_password` / `check_password`, reusing the password
hasher above):

```python
from fastapi_sm.database import User   # SQLAlchemy; for Tortoise use database.tortoise.User

# Transparent encrypted fields can be attached to any column by the consumer
# based on their own business needs — the library does not assume any business
# column.
```

## Login verification (storage-decoupled)

```python
from fastapi_sm.database import User
from fastapi_sm.login import login

admin = User(username="admin")
admin.set_password("secret")

def get_user(name: str):
    return admin if name == "admin" else None

user = login(get_user, "admin", "secret")   # returns user on success, None on failure
```

## Design notes

- **Pluggable backends**: `pysmx` and `gmssl_pyx` implement the same
  `CryptoBackend` interface, probed in `("pysmx", "gmssl_pyx")` order by default.
  SM4 ciphertext is cross-backend compatible; SM2 signatures are NOT guaranteed
  cross-backend verifiable due to encoding differences (same as snowland-jwt).
- **Pluggable ORMs**: `sqlalchemy` / `tortoise` subpackages are probed on demand;
  a missing dependency does not break imports.
- **Caller owns the key**: `EncryptedString.key` is required, supports per-column
  rotation, and does not rely on a global default (only `backends.set_encryption_key`
  is kept as a general-purpose helper).

## Dependencies

See `pyproject.toml` for the authoritative split. Required: `fastapi` +
`snowland-jwt`; one of the national-crypto backends (`snowland-smx` or
`gmssl-pyx`) is required at runtime; ORM adapters are optional.
