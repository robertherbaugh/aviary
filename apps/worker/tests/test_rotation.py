"""Unit tests for credential rotation helpers."""
import base64
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PublicFormat,
    PrivateFormat,
)

from aviary_worker.rotation import spki_pem_to_authorized_keys_line, finalize_rotation
from aviary_worker.config import Config


def _make_ed25519_spki_pem() -> str:
    """Generate a real Ed25519 SPKI PEM for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def _make_config(**kwargs) -> Config:
    defaults = dict(
        database_url="postgresql://test",
        encryption_key="0123456789abcdef0123456789abcdef",
        api_base_url="http://localhost:4000",
        api_grpc_target="localhost:50051",
        internal_api_token="test-token",
        pgboss_schema="pgboss",
        pgboss_queue="playbook-jobs",
        credential_rotation_queue="credential-rotation",
        poll_interval_ms=2000,
        command_timeout_s=30,
        worker_concurrency=5,
    )
    defaults.update(kwargs)
    return Config(**defaults)


class TestSpkiPemToAuthorizedKeysLine:
    def test_produces_ssh_ed25519_prefix(self) -> None:
        pem = _make_ed25519_spki_pem()
        line = spki_pem_to_authorized_keys_line(pem)
        assert line.startswith("ssh-ed25519 ")

    def test_base64_part_is_valid(self) -> None:
        pem = _make_ed25519_spki_pem()
        line = spki_pem_to_authorized_keys_line(pem)
        parts = line.split(" ")
        assert len(parts) == 2
        # Should decode without error
        wire = base64.b64decode(parts[1])
        assert len(wire) > 0

    def test_wire_format_starts_with_key_type(self) -> None:
        pem = _make_ed25519_spki_pem()
        line = spki_pem_to_authorized_keys_line(pem)
        wire = base64.b64decode(line.split(" ")[1])
        # First 4 bytes are the length of "ssh-ed25519" (11)
        key_type_len = struct.unpack(">I", wire[:4])[0]
        assert key_type_len == len("ssh-ed25519")
        key_type = wire[4 : 4 + key_type_len]
        assert key_type == b"ssh-ed25519"

    def test_wire_format_has_32_byte_raw_key(self) -> None:
        pem = _make_ed25519_spki_pem()
        line = spki_pem_to_authorized_keys_line(pem)
        wire = base64.b64decode(line.split(" ")[1])
        # Skip key_type field
        key_type_len = struct.unpack(">I", wire[:4])[0]
        offset = 4 + key_type_len
        # Next 4 bytes are length of raw key
        raw_len = struct.unpack(">I", wire[offset : offset + 4])[0]
        assert raw_len == 32  # Ed25519 public key is always 32 bytes

    def test_two_different_keys_produce_different_lines(self) -> None:
        pem1 = _make_ed25519_spki_pem()
        pem2 = _make_ed25519_spki_pem()
        assert spki_pem_to_authorized_keys_line(pem1) != spki_pem_to_authorized_keys_line(pem2)

    def test_raises_for_non_ed25519_key(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
        from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

        rsa_key = generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pub_pem = rsa_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
        with pytest.raises(ValueError, match="Only Ed25519"):
            spki_pem_to_authorized_keys_line(rsa_pub_pem)


class TestFinalizeRotation:
    @pytest.mark.asyncio
    async def test_sends_success_payload(self) -> None:
        config = _make_config()
        sent_payload = {}

        def fake_post(url, payload, headers, timeout_s=15):
            sent_payload.update({"url": url, "payload": payload, "headers": headers})

        with patch("aviary_worker.rotation._post_json", fake_post):
            await finalize_rotation(
                config,
                "hist-123",
                success=True,
                encrypted_new_private_key="enc-key-value",
            )

        assert sent_payload["payload"]["success"] is True
        assert sent_payload["payload"]["encryptedNewPrivateKey"] == "enc-key-value"
        assert "hist-123" in sent_payload["url"]
        assert sent_payload["headers"]["x-internal-token"] == "test-token"

    @pytest.mark.asyncio
    async def test_sends_failure_payload(self) -> None:
        config = _make_config()
        sent_payload = {}

        def fake_post(url, payload, headers, timeout_s=15):
            sent_payload.update({"payload": payload})

        with patch("aviary_worker.rotation._post_json", fake_post):
            await finalize_rotation(
                config,
                "hist-456",
                success=False,
                error_message="SSH connection refused",
            )

        assert sent_payload["payload"]["success"] is False
        assert sent_payload["payload"]["errorMessage"] == "SSH connection refused"

    @pytest.mark.asyncio
    async def test_does_not_include_key_in_failure_payload(self) -> None:
        config = _make_config()
        sent_payload = {}

        def fake_post(url, payload, headers, timeout_s=15):
            sent_payload.update({"payload": payload})

        with patch("aviary_worker.rotation._post_json", fake_post):
            await finalize_rotation(config, "hist-789", success=False, error_message="err")

        assert "encryptedNewPrivateKey" not in sent_payload["payload"]

    @pytest.mark.asyncio
    async def test_logs_and_does_not_raise_on_http_error(self) -> None:
        config = _make_config()

        def failing_post(url, payload, headers, timeout_s=15):
            raise OSError("connection refused")

        # Should not raise even if post fails
        with patch("aviary_worker.rotation._post_json", failing_post):
            await finalize_rotation(config, "hist-err", success=True, encrypted_new_private_key="k")
