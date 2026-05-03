from __future__ import annotations

import base64
import io
import json
import sqlite3
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization

from jwks_server.app import create_app
from jwks_server.config import MOCK_PASSWORD, MOCK_USERNAME, Settings


class AppHarness:
    def __init__(self, tmp_path) -> None:
        self.database_path = tmp_path / "totally_not_my_privateKeys.db"
        self.app = create_app(
            Settings.from_sources(
                database_path=str(self.database_path),
                encryption_key="test-secret-key",
            )
        )

    def call(
        self,
        path: str,
        method: str = "GET",
        body: bytes = b"",
        content_type: str = "application/json",
        auth: str | None = None,
        ip: str = "127.0.0.1",
        query: str = "",
    ) -> tuple[int, dict, list[tuple[str, str]]]:
        environ = {
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": content_type,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "REMOTE_ADDR": ip,
            "REQUEST_METHOD": method,
            "wsgi.input": io.BytesIO(body),
        }
        if auth:
            environ["HTTP_AUTHORIZATION"] = "Basic " + base64.b64encode(auth.encode("utf-8")).decode("ascii")

        result: dict[str, object] = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            result["status"] = int(status.split()[0])
            result["headers"] = headers

        payload = b"".join(self.app(environ, start_response))
        return int(result["status"]), json.loads(payload.decode("utf-8")), list(result["headers"])


def test_private_keys_are_encrypted_at_rest(tmp_path) -> None:
    harness = AppHarness(tmp_path)
    with sqlite3.connect(harness.database_path) as connection:
        rows = connection.execute("SELECT key FROM keys ORDER BY kid ASC").fetchall()
    assert rows
    assert not rows[0][0].startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_jwks_only_exposes_unexpired_keys(tmp_path) -> None:
    harness = AppHarness(tmp_path)
    status, body, _ = harness.call("/.well-known/jwks.json")
    assert status == 200
    assert len(body["keys"]) == 1

    valid_key = harness.app.repository.get_signing_key(expired=False)
    expired_key = harness.app.repository.get_signing_key(expired=True)
    assert body["keys"][0]["kid"] == str(valid_key.kid)
    assert body["keys"][0]["kid"] != str(expired_key.kid)


def test_auth_returns_a_valid_jwt_for_legacy_basic_credentials(tmp_path) -> None:
    harness = AppHarness(tmp_path)
    status, body, _ = harness.call(
        "/auth",
        method="POST",
        auth=f"{MOCK_USERNAME}:{MOCK_PASSWORD}",
    )
    assert status == 200

    signing_key = harness.app.repository.get_signing_key(expired=False)
    private_key = serialization.load_pem_private_key(signing_key.private_key_pem, password=None)
    claims = jwt.decode(
        body["token"],
        private_key.public_key(),
        algorithms=["RS256"],
        issuer="jwks-server",
    )
    assert claims["sub"] == MOCK_USERNAME


def test_register_returns_a_uuid_password_and_stores_a_hash(tmp_path) -> None:
    harness = AppHarness(tmp_path)
    status, body, _ = harness.call(
        "/register",
        method="POST",
        body=json.dumps({"username": "alice", "email": "alice@test.com"}).encode("utf-8"),
    )
    assert status == 201
    password = body["password"]
    uuid.UUID(password)

    user = harness.app.repository.get_user_by_username("alice")
    assert user is not None
    assert user.password_hash != password
    assert user.password_hash.startswith("$argon2")


def test_registered_users_can_authenticate_and_create_auth_logs(tmp_path) -> None:
    harness = AppHarness(tmp_path)
    _, body, _ = harness.call(
        "/register",
        method="POST",
        body=json.dumps({"username": "alice", "email": "alice@test.com"}).encode("utf-8"),
    )
    status, token_body, _ = harness.call(
        "/auth",
        method="POST",
        body=json.dumps({"username": "alice", "password": body["password"]}).encode("utf-8"),
        ip="10.10.10.10",
    )
    assert status == 200
    assert "token" in token_body

    user = harness.app.repository.get_user_by_username("alice")
    logs = harness.app.repository.list_auth_logs_for_user(user.id)
    assert user.last_login is not None
    assert len(logs) == 1
    assert logs[0].request_ip == "10.10.10.10"


def test_expired_auth_uses_the_expired_key_and_sets_a_past_expiry(tmp_path) -> None:
    harness = AppHarness(tmp_path)
    status, body, _ = harness.call(
        "/auth",
        method="POST",
        auth=f"{MOCK_USERNAME}:{MOCK_PASSWORD}",
        query="expired=true",
    )
    assert status == 200

    expired_key = harness.app.repository.get_signing_key(expired=True)
    header = jwt.get_unverified_header(body["token"])
    assert header["kid"] == str(expired_key.kid)

    private_key = serialization.load_pem_private_key(expired_key.private_key_pem, password=None)
    claims = jwt.decode(
        body["token"],
        private_key.public_key(),
        algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert claims["exp"] < int(time.time())


def test_method_restrictions_return_405(tmp_path) -> None:
    harness = AppHarness(tmp_path)
    auth_status, auth_body, _ = harness.call("/auth", method="GET")
    jwks_status, jwks_body, _ = harness.call("/.well-known/jwks.json", method="POST")
    register_status, register_body, _ = harness.call("/register", method="GET")

    assert auth_status == 405
    assert auth_body["error"] == "Method not allowed."
    assert jwks_status == 405
    assert jwks_body["error"] == "Method not allowed."
    assert register_status == 405
    assert register_body["error"] == "Method not allowed."


def test_auth_rate_limit_caps_a_burst_and_only_logs_successes(tmp_path) -> None:
    harness = AppHarness(tmp_path)
    _, body, _ = harness.call(
        "/register",
        method="POST",
        body=json.dumps({"username": "alice", "email": "alice@test.com"}).encode("utf-8"),
    )
    payload = json.dumps({"username": "alice", "password": body["password"]}).encode("utf-8")

    statuses = []
    for _ in range(10):
        time.sleep(0.1)
        statuses.append(harness.call("/auth", method="POST", body=payload)[0])
    statuses.append(harness.call("/auth", method="POST", body=payload)[0])

    user = harness.app.repository.get_user_by_username("alice")
    logs = harness.app.repository.list_auth_logs_for_user(user.id)
    assert statuses[:-1] == [200] * 10
    assert statuses[-1] == 429
    assert len(logs) == 10
