from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request


BASE_URL = "http://127.0.0.1:8080"


def request(path: str, method: str = "GET", payload: dict | None = None) -> tuple[int, dict]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE_URL + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def main() -> int:
    register_status, register_body = request(
        "/register",
        method="POST",
        payload={"username": "smoke-user", "email": "smoke-user@test.com"},
    )
    if register_status not in {200, 201}:
        print(f"register failed: {register_status} {register_body}")
        return 1

    password = register_body["password"]
    auth_status, auth_body = request(
        "/auth",
        method="POST",
        payload={"username": "smoke-user", "password": password},
    )
    expired_status, expired_body = request(
        "/auth?expired=true",
        method="POST",
        payload={"username": "smoke-user", "password": password},
    )
    jwks_status, jwks_body = request("/.well-known/jwks.json")

    print("register:", register_status)
    print("auth:", auth_status, "token" in auth_body)
    print("expired auth:", expired_status, "token" in expired_body)
    print("jwks:", jwks_status, len(jwks_body.get("keys", [])))

    return 0 if auth_status == 200 and expired_status == 200 and jwks_status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
