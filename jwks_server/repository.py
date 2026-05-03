from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from jwks_server.crypto import KeyCipher, generate_private_key_pem, jwk_from_private_key_pem


KEYS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""".strip()

USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
""".strip()

AUTH_LOGS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""".strip()


@dataclass(frozen=True)
class StoredKey:
    kid: int
    private_key_pem: bytes
    exp: int


@dataclass(frozen=True)
class StoredUser:
    id: int
    username: str
    password_hash: str
    email: str
    date_registered: str
    last_login: str | None


@dataclass(frozen=True)
class StoredAuthLog:
    id: int
    request_ip: str
    request_timestamp: str
    user_id: int


class Repository:
    def __init__(self, database_path: str, key_cipher: KeyCipher) -> None:
        self.database_path = Path(database_path)
        self.key_cipher = key_cipher

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(KEYS_TABLE_SQL)
            connection.execute(USERS_TABLE_SQL)
            connection.execute(AUTH_LOGS_TABLE_SQL)
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

    def get_signing_key(self, expired: bool) -> StoredKey | None:
        now = self.now()
        comparator = "<=" if expired else ">"
        ordering = "DESC" if expired else "ASC"
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT kid, key, exp FROM keys WHERE exp {comparator} ? ORDER BY exp {ordering} LIMIT 1",
                (now,),
            ).fetchone()
        if row is None:
            return None
        return StoredKey(
            kid=int(row["kid"]),
            private_key_pem=self.key_cipher.decrypt(row["key"]),
            exp=int(row["exp"]),
        )

    def build_jwks(self) -> dict[str, list[dict[str, str]]]:
        now = self.now()
        keys = [key for key in self.list_keys() if key.exp > now]
        return {"keys": [jwk_from_private_key_pem(key.private_key_pem, key.kid) for key in keys]}

    def create_user(self, username: str, email: str, password_hash: str) -> int:
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users (username, password_hash, email)
                    VALUES (?, ?, ?)
                    """,
                    (username, password_hash, email),
                )
                connection.commit()
                return int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username or email is already registered.") from exc

    def ensure_mock_user(self, username: str, email: str, password_hash: str) -> None:
        if self.get_user_by_username(username) is None:
            self.create_user(username=username, email=email, password_hash=password_hash)

    def get_user_by_username(self, username: str) -> StoredUser | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, username, password_hash, email, date_registered, last_login
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        if row is None:
            return None
        return StoredUser(
            id=int(row["id"]),
            username=str(row["username"]),
            password_hash=str(row["password_hash"]),
            email=str(row["email"]),
            date_registered=str(row["date_registered"]),
            last_login=str(row["last_login"]) if row["last_login"] is not None else None,
        )

    def update_last_login(self, user_id: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,),
            )
            connection.commit()

    def create_auth_log(self, request_ip: str, user_id: int) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO auth_logs (request_ip, user_id)
                VALUES (?, ?)
                """,
                (request_ip, user_id),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def list_auth_logs_for_user(self, user_id: int) -> list[StoredAuthLog]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, request_ip, request_timestamp, user_id
                FROM auth_logs
                WHERE user_id = ?
                ORDER BY id DESC
                """,
                (user_id,),
            ).fetchall()
        return [
            StoredAuthLog(
                id=int(row["id"]),
                request_ip=str(row["request_ip"]),
                request_timestamp=str(row["request_timestamp"]),
                user_id=int(row["user_id"]),
            )
            for row in rows
        ]

    def now(self) -> int:
        return int(time.time())

    def _count_keys(self, query: str, params: tuple[object, ...]) -> int:
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
        return int(row[0]) if row else 0

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection
