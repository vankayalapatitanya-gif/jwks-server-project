from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_private_key_pem() -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def jwk_from_private_key_pem(private_key_pem: bytes, kid: int) -> dict[str, str]:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    public_numbers = private_key.public_key().public_numbers()
    return {
        "alg": "RS256",
        "e": _base64url_uint(public_numbers.e),
        "kid": str(kid),
        "kty": "RSA",
        "n": _base64url_uint(public_numbers.n),
        "use": "sig",
    }


@dataclass(frozen=True)
class KeyCipher:
    secret: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "_key", hashlib.sha256(self.secret.encode("utf-8")).digest())
        object.__setattr__(self, "_aesgcm", AESGCM(self._key))

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        nonce = ciphertext[:12]
        payload = ciphertext[12:]
        return self._aesgcm.decrypt(nonce, payload, None)
