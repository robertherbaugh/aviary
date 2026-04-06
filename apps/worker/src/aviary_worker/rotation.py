"""
Credential rotation logic for SSH keypairs.

Flow:
  1. Receive job payload: rotationHistoryId, credentialId, encryptedNewPrivateKey, newPublicKeyPem
  2. Decrypt old and new private keys
  3. For each server linked to the credential:
     a. Connect with old key
     b. Append new public key to authorized_keys
     c. Verify new key works (test SSH connection)
     d. Remove old public key from authorized_keys
  4. Report success/failure to API finalize endpoint
"""

import asyncio
import base64
import json
import logging
import shlex
import struct
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import asyncpg
import asyncssh
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from .config import Config
from .crypto import decrypt_secret
from .ssh import resolve_ssh_username

LOGGER = logging.getLogger("aviary-worker.rotation")

CREDENTIAL_ROTATION_QUEUE = "credential-rotation"


@dataclass
class RotationJob:
    rotation_history_id: str
    credential_id: str
    encrypted_new_private_key: str
    new_public_key_pem: str


@dataclass
class ServerInfo:
    id: str
    hostname: str
    ip_address: str
    port: int
    username: Optional[str]


def spki_pem_to_authorized_keys_line(pem: str) -> str:
    """Convert a SPKI PEM public key to an authorized_keys line (ssh-ed25519 ...)."""
    pub_key = load_pem_public_key(pem.encode())
    if not isinstance(pub_key, Ed25519PublicKey):
        raise ValueError("Only Ed25519 public keys are supported for rotation")
    raw = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_type = b"ssh-ed25519"

    def ssh_string(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    wire = ssh_string(key_type) + ssh_string(raw)
    return f"ssh-ed25519 {base64.b64encode(wire).decode()}"


def _post_json(url: str, payload: Dict[str, Any], headers: Dict[str, str], timeout_s: int = 15) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as response:  # noqa: S310
        response.read()


async def finalize_rotation(
    config: Config,
    rotation_history_id: str,
    *,
    success: bool,
    encrypted_new_private_key: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    url = (
        f"{config.api_base_url.rstrip('/')}"
        f"/api/v1/internal/credentials/rotation/{rotation_history_id}/finalize"
    )
    payload: Dict[str, Any] = {"success": success}
    if success and encrypted_new_private_key:
        payload["encryptedNewPrivateKey"] = encrypted_new_private_key
    if error_message:
        payload["errorMessage"] = error_message

    headers = {"x-internal-token": config.internal_api_token}
    try:
        await asyncio.to_thread(_post_json, url, payload, headers)
        LOGGER.info("Rotation %s: finalize sent success=%s", rotation_history_id, success)
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Rotation %s: failed to send finalize", rotation_history_id, exc_info=exc)


async def get_linked_servers(conn: asyncpg.Connection, credential_id: str) -> List[ServerInfo]:
    rows = await conn.fetch(
        """
        SELECT s.id, s.hostname, s.ip_address, s.port, s.username
        FROM servers s
        JOIN server_credentials sc ON sc.server_id = s.id
        WHERE sc.credential_id = $1 AND s.active = true
        """,
        credential_id,
    )
    return [
        ServerInfo(
            id=str(row["id"]),
            hostname=str(row["hostname"]),
            ip_address=str(row["ip_address"]),
            port=int(row["port"]),
            username=str(row["username"]) if row["username"] else None,
        )
        for row in rows
    ]


async def get_credential_username(conn: asyncpg.Connection, credential_id: str) -> Optional[str]:
    row = await conn.fetchrow("SELECT username FROM credentials WHERE id = $1", credential_id)
    return str(row["username"]) if row else None


async def get_old_public_key_line(ssh_conn: asyncssh.SSHClientConnection) -> Optional[str]:
    """Return the authorized_keys entry for the current connection's key."""
    result = await ssh_conn.run("cat ~/.ssh/authorized_keys 2>/dev/null || true", check=False)
    return result.stdout.strip() if result.stdout else None


async def rotate_on_server(
    server: ServerInfo,
    old_private_key_pem: str,
    new_private_key_pem: str,
    new_public_key_line: str,
    cred_username: str,
    command_timeout_s: int,
) -> None:
    """
    On the given server:
    1. Connect with old key
    2. Append new public key to authorized_keys
    3. Verify new key connects
    4. Remove old public key from authorized_keys
    """
    resolved_user = resolve_ssh_username(server.username, cred_username)
    base_connect = {
        "host": server.ip_address,
        "port": server.port,
        "username": resolved_user,
        "known_hosts": None,
    }

    LOGGER.info(
        "Rotation: connecting to server %s (%s:%s) with old key",
        server.hostname,
        server.ip_address,
        server.port,
    )

    old_key = asyncssh.import_private_key(old_private_key_pem)
    new_key = asyncssh.import_private_key(new_private_key_pem)

    # Step 1: Connect with old key and deploy new public key
    async with asyncssh.connect(**base_connect, client_keys=[old_key]) as ssh_old:
        # Read current authorized_keys content
        read_result = await asyncio.wait_for(
            ssh_old.run("cat ~/.ssh/authorized_keys 2>/dev/null || true", check=False),
            timeout=command_timeout_s,
        )
        current_content = read_result.stdout or ""

        # Append new public key if not already present
        if new_public_key_line not in current_content:
            escaped_key = shlex.quote(new_public_key_line)
            append_cmd = f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo {escaped_key} >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
            append_result = await asyncio.wait_for(
                ssh_old.run(append_cmd, check=False),
                timeout=command_timeout_s,
            )
            if append_result.exit_status != 0:
                raise RuntimeError(
                    f"Failed to append new public key on {server.hostname}: {append_result.stderr}"
                )

        LOGGER.info("Rotation: new public key deployed on %s", server.hostname)

    # Step 2: Verify new key works
    LOGGER.info("Rotation: verifying new key on %s", server.hostname)
    async with asyncssh.connect(**base_connect, client_keys=[new_key]) as ssh_new:
        verify_result = await asyncio.wait_for(
            ssh_new.run("echo ok", check=False),
            timeout=command_timeout_s,
        )
        if verify_result.exit_status != 0 or verify_result.stdout.strip() != "ok":
            raise RuntimeError(
                f"New key verification failed on {server.hostname}: {verify_result.stderr}"
            )
        LOGGER.info("Rotation: new key verified on %s", server.hostname)

        # Step 3: Remove old public key from authorized_keys
        old_pub_key = old_key.export_public_key("openssh").decode().strip()
        # Use Python to filter out the old key line safely
        remove_cmd = (
            f"python3 -c \""
            f"import pathlib; "
            f"p = pathlib.Path.home() / '.ssh' / 'authorized_keys'; "
            f"lines = p.read_text().splitlines() if p.exists() else []; "
            f"old = {repr(old_pub_key)}; "
            f"filtered = [l for l in lines if l.strip() != old.strip()]; "
            f"p.write_text('\\n'.join(filtered) + ('\\n' if filtered else ''))"
            f"\""
        )
        remove_result = await asyncio.wait_for(
            ssh_new.run(remove_cmd, check=False),
            timeout=command_timeout_s,
        )
        if remove_result.exit_status != 0:
            LOGGER.warning(
                "Rotation: failed to remove old key from authorized_keys on %s (non-fatal): %s",
                server.hostname,
                remove_result.stderr,
            )

    LOGGER.info("Rotation: completed on server %s", server.hostname)


async def run_rotation_job(pool: asyncpg.Pool, config: Config, job: RotationJob) -> None:
    LOGGER.info(
        "Rotation: starting job historyId=%s credentialId=%s",
        job.rotation_history_id,
        job.credential_id,
    )

    try:
        async with pool.acquire() as conn:
            old_encrypted = await conn.fetchval(
                "SELECT encrypted_value FROM credentials WHERE id = $1",
                job.credential_id,
            )
            if not old_encrypted:
                raise RuntimeError(f"Credential {job.credential_id} not found")

            cred_username = await get_credential_username(conn, job.credential_id)
            if not cred_username:
                raise RuntimeError(f"Could not resolve username for credential {job.credential_id}")

            servers = await get_linked_servers(conn, job.credential_id)

        old_private_key_pem = decrypt_secret(str(old_encrypted), config.encryption_key)
        new_private_key_pem = decrypt_secret(job.encrypted_new_private_key, config.encryption_key)
        new_public_key_line = spki_pem_to_authorized_keys_line(job.new_public_key_pem)

        if not servers:
            LOGGER.info(
                "Rotation: credentialId=%s has no active linked servers — skipping SSH steps",
                job.credential_id,
            )
        else:
            for server in servers:
                await rotate_on_server(
                    server=server,
                    old_private_key_pem=old_private_key_pem,
                    new_private_key_pem=new_private_key_pem,
                    new_public_key_line=new_public_key_line,
                    cred_username=cred_username,
                    command_timeout_s=config.command_timeout_s,
                )

        await finalize_rotation(
            config,
            job.rotation_history_id,
            success=True,
            encrypted_new_private_key=job.encrypted_new_private_key,
        )
        LOGGER.info("Rotation: job historyId=%s completed successfully", job.rotation_history_id)

    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Rotation: job historyId=%s failed", job.rotation_history_id, exc_info=exc)
        await finalize_rotation(
            config,
            job.rotation_history_id,
            success=False,
            error_message=f"{type(exc).__name__}: {exc}",
        )
