from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

from jwks_server.config import JWT_ISSUER, JWT_LIFETIME_SECONDS, MOCK_PASSWORD, MOCK_USERNAME, Settings
from jwks_server.crypto import KeyCipher, sign_jwt
from jwks_server.repository import Repository


class JWKSServer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.repository = Repository(settings.database_path, KeyCipher(settings.encryption_key))
        self.repository.initialize()
        self.repository.ensure_seed_keys()

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET").upper()

        if path == "/.well-known/jwks.json":
            if method != "GET":
                return self._method_not_allowed(start_response, ["GET"])
            return self._json_response(start_response, 200, self.repository.build_jwks())

        if path == "/auth":
            if method != "POST":
                return self._method_not_allowed(start_response, ["POST"])
            return self._handle_auth(environ, start_response)

        return self._json_response(
            start_response,
            404,
            {"message": "Route not found.", "path": path},
        )

    def _handle_auth(self, environ, start_response):
        username, password = self._extract_credentials(environ)
        if username != MOCK_USERNAME or password != MOCK_PASSWORD:
            return self._json_response(
                start_response,
                401,
                {"error": "Invalid credentials."},
                headers=[("WWW-Authenticate", 'Basic realm="jwks-server"')],
            )

        query = parse_qs(environ.get("QUERY_STRING", ""))
        expired = "expired" in query
        signing_key = self.repository.get_signing_key(expired=expired)
        if signing_key is None:
            return self._json_response(start_response, 500, {"error": "No signing key available."})

        jwt_exp = signing_key.exp if expired else max(signing_key.exp, self.repository.now() + JWT_LIFETIME_SECONDS)
        token = sign_jwt(
            private_key_pem=signing_key.private_key_pem,
            kid=signing_key.kid,
            issuer=JWT_ISSUER,
            subject=username,
            expires_at=jwt_exp,
            issued_at=self.repository.now(),
        )
        return self._json_response(start_response, 200, {"token": token})

    def _extract_credentials(self, environ) -> tuple[str, str]:
        auth_header = environ.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                username, password = decoded.split(":", 1)
                return username, password
            except (ValueError, UnicodeDecodeError):
                return "", ""

        body_length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(body_length) if body_length else b""
        content_type = environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower()

        if content_type == "application/json":
            try:
                payload = json.loads(body.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return "", ""
            return str(payload.get("username", "")), str(payload.get("password", ""))

        if content_type == "application/x-www-form-urlencoded":
            parsed = parse_qs(body.decode("utf-8"))
            return parsed.get("username", [""])[0], parsed.get("password", [""])[0]

        return "", ""

    def _json_response(self, start_response, status_code: int, payload: dict, headers=None):
        body = json.dumps(payload).encode("utf-8")
        all_headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ]
        if headers:
            all_headers.extend(headers)
        start_response(f"{status_code} {self._status_text(status_code)}", all_headers)
        return [body]

    def _method_not_allowed(self, start_response, allowed_methods: list[str]):
        return self._json_response(
            start_response,
            405,
            {"error": "Method not allowed."},
            headers=[("Allow", ", ".join(allowed_methods))],
        )

    def _status_text(self, status_code: int) -> str:
        phrases = {
            200: "OK",
            401: "Unauthorized",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }
        return phrases.get(status_code, "OK")


def create_app(settings: Settings | None = None) -> JWKSServer:
    return JWKSServer(settings or Settings.from_sources())


def serve(settings: Settings | None = None) -> None:
    app = create_app(settings)
    with make_server(app.settings.host, app.settings.port, app) as server:
        server.serve_forever()
