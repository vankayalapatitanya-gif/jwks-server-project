from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    database_path: str
    encryption_key: str

    @classmethod
    def from_sources(
        cls,
        host: str | None = None,
        port: int | None = None,
        database_path: str | None = None,
        encryption_key: str | None = None,
    ) -> "Settings":
        return cls(
            host=host or cls.default_host(),
            port=port or cls.default_port(),
            database_path=database_path or cls.default_database_path(),
            encryption_key=encryption_key or cls.default_encryption_key(),
        )

    @staticmethod
    def default_host() -> str:
        return os.environ.get("JWKS_HOST", "127.0.0.1")

    @staticmethod
    def default_port() -> int:
        return int(os.environ.get("JWKS_PORT", "8080"))

    @staticmethod
    def default_database_path() -> str:
        return os.environ.get("JWKS_DB_PATH", "totally_not_my_privateKeys.db")

    @staticmethod
    def default_encryption_key() -> str:
        key = os.environ.get("NOT_MY_KEY")
        if not key:
            raise RuntimeError("The NOT_MY_KEY environment variable must be set.")
        return key
