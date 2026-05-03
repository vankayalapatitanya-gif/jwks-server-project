from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, VerifyMismatchError


def build_password_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=1,
        memory_cost=512,
        parallelism=1,
        hash_len=32,
        salt_len=16,
    )


def verify_password(password_hasher: PasswordHasher, password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (Argon2Error, VerifyMismatchError):
        return False
