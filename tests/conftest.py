import base64
import datetime
import json
from dataclasses import dataclass
from pathlib import Path

import merkle_ref as ref
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass
class SignedEntry:
    """A fake Rekor log entry plus the artifact it signs."""

    artifact: Path
    log_index: int
    entry: dict
    leaves: list[bytes]
    key: ec.EllipticCurvePrivateKey
    cert_pem: bytes


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def make_cert(key: ec.EllipticCurvePrivateKey) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def signed_entry(tmp_path, ec_key):
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"hello rekor\n")
    signature = ec_key.sign(artifact.read_bytes(), ec.ECDSA(hashes.SHA256()))
    cert_pem = make_cert(ec_key)

    body = json.dumps(
        {
            "spec": {
                "signature": {
                    "content": b64(signature),
                    "publicKey": {"content": b64(cert_pem)},
                }
            }
        }
    ).encode()
    encoded_body = b64(body)

    # place this entry at index 2 of a 5-leaf tree
    log_index = 2
    leaves = ref.make_leaves(5)
    leaves[log_index] = body
    entry = {
        "body": encoded_body,
        "verification": {
            "inclusionProof": {
                "logIndex": log_index,
                "treeSize": len(leaves),
                "rootHash": ref.root(leaves).hex(),
                "hashes": [h.hex() for h in ref.inclusion_proof(log_index, leaves)],
            }
        },
    }
    return SignedEntry(artifact, log_index, entry, leaves, ec_key, cert_pem)


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status

    def raise_for_status(self):
        if self.status >= 400:
            import requests

            raise requests.HTTPError(f"{self.status} error")

    def json(self):
        return self.payload
