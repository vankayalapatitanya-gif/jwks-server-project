from __future__ import annotations

import json
from wsgiref.simple_server import make_server

from jwks_server.config import Settings
from jwks_server.crypto import KeyCipher
from jwks_server.repository import Repository


class JWKSServer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.repository = Repository(settings.database_path, KeyCipher(settings.encryption_key))
        self.repository.initialize()
        self.repository.ensure_seed_keys()

    def __call__(self, environ, start_response):
        payload = json.dumps(
            {
                "message": "JWKS server bootstrap is running.",
                "path": environ.get("PATH_INFO", "/"),
            }
        ).encode("utf-8")
        start_response(
            "404 Not Found",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(payload))),
            ],
        )
        return [payload]


def create_app(settings: Settings | None = None) -> JWKSServer:
    return JWKSServer(settings or Settings.from_sources())


def serve(settings: Settings | None = None) -> None:
    app = create_app(settings)
    with make_server(app.settings.host, app.settings.port, app) as server:
        server.serve_forever()
