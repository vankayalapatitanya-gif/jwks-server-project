from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from jwks_server.crypto import KeyCipher, generate_private_key_pem


KEYS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""".strip()


@dataclass(frozen=True)
class StoredKey:
    kid: int
    private_key_pem: bytes
    exp: int


class Repository:
    def __init__(self, database_path: str, key_cipher: KeyCipher) -> None:
        self.database_path = Path(database_path)
        self.key_cipher = key_cipher

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(KEYS_TABLE_SQL)
            connection.commit()

    def ensure_seed_keys(self) -> None:
        now = int(time.time())
        valid_exists = self._count_keys("SELECT COUNT(*) FROM keys WHERE exp > ?", (now,))
        expired_exists = self._count_keys("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))

        if not expired_exists:
            self.store_private_key(generate_private_key_pem(), now - 300)
        if not valid_exists:
            self.store_private_key(generate_private_key_pem(), now + 3600)

    def store_private_key(self, private_key_pem: bytes, exp: int) -> int:
        encrypted_key = self.key_cipher.encrypt(private_key_pem)
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (encrypted_key, exp),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def list_keys(self) -> list[StoredKey]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT kid, key, exp FROM keys ORDER BY kid ASC"
            ).fetchall()
        return [
            StoredKey(
                kid=int(row["kid"]),
                private_key_pem=self.key_cipher.decrypt(row["key"]),
                exp=int(row["exp"]),
            )
            for row in rows
        ]

    def _count_keys(self, query: str, params: tuple[object, ...]) -> int:
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
        return int(row[0]) if row else 0

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection
