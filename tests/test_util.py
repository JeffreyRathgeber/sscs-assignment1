import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from util import UnsupportedKeyError, extract_public_key, verify_artifact_signature

PEM = serialization.Encoding.PEM
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def public_pem(key):
    return key.public_key().public_bytes(PEM, SPKI)


def sign(key, data):
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def test_extract_public_key_returns_certificate_key(signed_entry):
    assert extract_public_key(signed_entry.cert_pem) == public_pem(signed_entry.key)


def test_extract_public_key_rejects_garbage():
    with pytest.raises(ValueError):
        extract_public_key(b"not a certificate")


def test_verify_artifact_signature_accepts_valid_signature(tmp_path, ec_key):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"payload")
    assert (
        verify_artifact_signature(
            sign(ec_key, b"payload"), public_pem(ec_key), str(artifact)
        )
        is None
    )


def test_verify_artifact_signature_rejects_modified_artifact(tmp_path, ec_key):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"payload")
    signature = sign(ec_key, b"payload")
    artifact.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_artifact_signature(signature, public_pem(ec_key), str(artifact))


def test_verify_artifact_signature_rejects_wrong_key(tmp_path, ec_key):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"payload")
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_artifact_signature(
            sign(ec_key, b"payload"), public_pem(other), str(artifact)
        )


def test_verify_artifact_signature_rejects_non_ec_key(tmp_path):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"payload")
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(UnsupportedKeyError):
        verify_artifact_signature(b"sig", public_pem(rsa_key), str(artifact))


def test_verify_artifact_signature_missing_file(tmp_path, ec_key):
    with pytest.raises(FileNotFoundError):
        verify_artifact_signature(
            b"sig", public_pem(ec_key), str(tmp_path / "does-not-exist")
        )
