import argparse

from jwks_server.app import serve
from jwks_server.config import Settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the JWKS server.")
    parser.add_argument("--host", default=Settings.default_host())
    parser.add_argument("--port", type=int, default=Settings.default_port())
    parser.add_argument("--database", default=Settings.default_database_path())
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings.from_sources(
        host=args.host,
        port=args.port,
        database_path=args.database,
    )
    serve(settings)
    return 0
