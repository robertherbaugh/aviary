import asyncio
import json
import logging
import re
import shlex
import shutil
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import asyncpg
import asyncssh
import grpc
from dotenv import load_dotenv

from .config import Config, load_config
from .crypto import decrypt_secret
from .job_results import build_failure_job_result
from .parsers import parse_output
from .proto import job_events_pb2, job_events_pb2_grpc
from .rotation import RotationJob, run_rotation_job
from .ssh import resolve_ssh_username

LOGGER = logging.getLogger("aviary-worker")


@dataclass
class QueueClaim:
    queue_job_id: str
    app_job_id: str


@dataclass
class AppJob:
    id: str
    playbook_id: str
    server_id: str
    use_sudo: bool


def _safe_identifier(value: str) -> str:
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", value):
        raise ValueError(f"Invalid identifier: {value}")
    return value


def _to_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def _post_json(url: str, payload: Dict[str, Any], headers: Dict[str, str], timeout_s: int = 10) -> Dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as response:  # noqa: S310
        body = response.read().decode("utf-8")
        if not body:
            return {}
        return json.loads(body)


def _apply_sudo(command: str, use_sudo: bool) -> str:
    if not use_sudo:
        return command
    stripped = command.lstrip()
    if stripped.startswith("sudo ") or stripped.startswith("sudo\t") or stripped == "sudo":
        return command
    return f"sudo -n sh -lc {shlex.quote(command)}"


async def claim_queue_job(conn: asyncpg.Connection, schema: str, queue_name: str) -> Optional[QueueClaim]:
    safe_schema = _safe_identifier(schema)

    row = await conn.fetchrow(
        f"""
        WITH next AS (
          SELECT id
          FROM {safe_schema}.job
          WHERE name = $1
            AND state < 'active'
            AND start_after < now()
          ORDER BY priority DESC, created_on, id
          LIMIT 1
          FOR UPDATE SKIP LOCKED
        )
        UPDATE {safe_schema}.job j
        SET state = 'active',
            started_on = now(),
            retry_count = CASE WHEN started_on IS NOT NULL THEN retry_count + 1 ELSE retry_count END
        FROM next
        WHERE j.id = next.id
        RETURNING j.id, j.data
        """,
        queue_name,
    )

    if not row:
        return None

    payload = row["data"] or {}
    if isinstance(payload, str):
        payload = json.loads(payload)

    job_id = payload.get("jobId") or payload.get("job_id")
    if not isinstance(job_id, str):
        await mark_queue_job_failed(
            conn,
            schema=schema,
            queue_name=queue_name,
            queue_job_id=str(row["id"]),
            output={"error": "queue payload missing app job id"},
        )
        return None

    return QueueClaim(queue_job_id=str(row["id"]), app_job_id=job_id)


async def mark_queue_job_completed(
    conn: asyncpg.Connection,
    *,
    schema: str,
    queue_name: str,
    queue_job_id: str,
    output: Dict[str, Any],
) -> None:
    safe_schema = _safe_identifier(schema)
    await conn.execute(
        f"""
        UPDATE {safe_schema}.job
        SET completed_on = now(), state = 'completed', output = $3::jsonb
        WHERE name = $1 AND id = $2::uuid AND state = 'active'
        """,
        queue_name,
        queue_job_id,
        _to_json(output),
    )


async def mark_queue_job_failed(
    conn: asyncpg.Connection,
    *,
    schema: str,
    queue_name: str,
    queue_job_id: str,
    output: Dict[str, Any],
) -> None:
    safe_schema = _safe_identifier(schema)
    await conn.execute(
        f"""
        UPDATE {safe_schema}.job
        SET completed_on = now(), state = 'failed', output = $3::jsonb
        WHERE name = $1 AND id = $2::uuid AND state = 'active'
        """,
        queue_name,
        queue_job_id,
        _to_json(output),
    )


async def get_app_job(conn: asyncpg.Connection, app_job_id: str) -> Optional[AppJob]:
    row = await conn.fetchrow(
        "SELECT id, playbook_id, server_id, use_sudo FROM jobs WHERE id = $1",
        app_job_id,
    )
    if not row:
        return None

    return AppJob(
        id=str(row["id"]),
        playbook_id=str(row["playbook_id"]),
        server_id=str(row["server_id"]),
        use_sudo=bool(row["use_sudo"]),
    )


async def get_job_context(conn: asyncpg.Connection, job: AppJob) -> Dict[str, Any]:
    playbook = await conn.fetchrow("SELECT id, name FROM playbooks WHERE id = $1", job.playbook_id)
    if not playbook:
        raise RuntimeError(f"Playbook {job.playbook_id} not found")

    steps = await conn.fetch(
        """
        SELECT "order", command, expected_exit_code, parse_rule
        FROM playbook_steps
        WHERE playbook_id = $1
        ORDER BY "order" ASC
        """,
        job.playbook_id,
    )

    server = await conn.fetchrow(
        """
        SELECT id, hostname, ip_address, port, username
        FROM servers
        WHERE id = $1
        """,
        job.server_id,
    )
    if not server:
        raise RuntimeError(f"Server {job.server_id} not found")

    credential = await conn.fetchrow(
        """
        SELECT c.id, c.type, c.username, c.encrypted_value
        FROM credentials c
        JOIN server_credentials sc ON sc.credential_id = c.id
        WHERE sc.server_id = $1
        LIMIT 1
        """,
        job.server_id,
    )

    if not credential:
        raise RuntimeError(f"No credential attached to server {job.server_id}")

    return {
        "playbook": playbook,
        "steps": steps,
        "server": server,
        "credential": credential,
    }


async def evaluate_alerts(conn: asyncpg.Connection, server_id: str, metrics: Dict[str, float]) -> None:
    if not metrics:
        return

    alerts = await conn.fetch("SELECT id, metric, threshold, operator, severity FROM alerts WHERE server_id = $1", server_id)

    for alert in alerts:
        metric = alert["metric"]
        if metric not in metrics:
            continue

        value = float(metrics[metric])
        threshold = float(alert["threshold"])
        operator = alert["operator"]

        triggered = False
        if operator == "gt":
            triggered = value > threshold
        elif operator == "lt":
            triggered = value < threshold
        elif operator == "eq":
            triggered = value == threshold

        if not triggered:
            continue

        message = f"{alert['severity'].upper()} {metric}={value} {operator} {threshold}"

        await conn.execute("UPDATE alerts SET last_triggered_at = NOW() WHERE id = $1", alert["id"])
        await conn.execute(
            """
            INSERT INTO notifications (id, alert_id, triggered_at, message, acknowledged)
            VALUES ($1, $2, NOW(), $3, false)
            """,
            str(uuid4()),
            alert["id"],
            message,
        )


async def evaluate_alerts_via_api(config: Config, job_id: str, server_id: str, metrics: Dict[str, float]) -> bool:
    if not metrics:
        return True

    payload = {
        "metrics": [{"serverId": server_id, "metric": metric, "value": value} for metric, value in metrics.items()]
    }
    url = f"{config.api_base_url.rstrip('/')}/api/v1/internal/jobs/{job_id}/evaluate-alerts"
    headers = {"x-internal-token": config.internal_api_token}

    try:
        await asyncio.to_thread(_post_json, url, payload, headers)
        return True
    except Exception:  # noqa: BLE001
        LOGGER.exception("Job %s: failed to evaluate alerts via API endpoint %s", job_id, url)
        return False


class JobEventStream:
    def __init__(self, config: Config, job_id: str) -> None:
        self._config = config
        self._job_id = job_id
        self._seq = 0
        self._channel: Optional[grpc.aio.Channel] = None
        self._call: Optional[grpc.aio.StreamUnaryCall] = None
        self._disabled = False

    async def __aenter__(self) -> "JobEventStream":
        target = self._config.api_grpc_target.strip()
        if not target:
            self._disabled = True
            return self

        self._channel = grpc.aio.insecure_channel(target)
        stub = job_events_pb2_grpc.JobEventIngressStub(self._channel)
        self._call = stub.PublishEvents(metadata=(("x-internal-token", self._config.internal_api_token),))
        return self

    async def emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if self._disabled or self._call is None:
            return

        self._seq += 1
        request = job_events_pb2.PublishEventRequest(
            job_id=self._job_id,
            seq=self._seq,
            event_type=event_type,
            payload_json=_to_json(payload),
            emitted_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )

        try:
            await self._call.write(request)
        except Exception:  # noqa: BLE001
            self._disabled = True
            LOGGER.exception("Job %s: failed to publish stream event type=%s", self._job_id, event_type)

    async def __aexit__(self, *_args: object) -> None:
        if self._call is not None and not self._disabled:
            try:
                await self._call.done_writing()
                await self._call
            except Exception:  # noqa: BLE001
                LOGGER.exception("Job %s: failed to finalize gRPC event stream", self._job_id)

        if self._channel is not None:
            await self._channel.close()


async def execute_step(
    ssh_conn: asyncssh.SSHClientConnection,
    command: str,
    timeout_s: int,
) -> Dict[str, Any]:
    result = await asyncio.wait_for(ssh_conn.run(command, check=False), timeout=timeout_s)
    return {
        "exit_code": int(result.exit_status),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


async def insert_job_result(conn: asyncpg.Connection, job_id: str, result: Dict[str, Any]) -> None:
    await conn.execute(
        """
        INSERT INTO job_results (id, job_id, step_order, command, exit_code, stdout, stderr, duration_ms, parsed_values)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
        """,
        str(uuid4()),
        job_id,
        int(result["step_order"]),
        str(result["command"]),
        int(result["exit_code"]),
        str(result["stdout"]),
        str(result["stderr"]),
        int(result["duration_ms"]),
        json.dumps(result["parsed_values"]),
    )


async def safe_insert_job_result(conn: asyncpg.Connection, job_id: str, result: Dict[str, Any]) -> bool:
    try:
        await insert_job_result(conn, job_id, result)
        LOGGER.info(
            "Job %s: recorded result step=%s command=%s exit=%s",
            job_id,
            result["step_order"],
            result["command"],
            result["exit_code"],
        )
        return True
    except Exception:  # noqa: BLE001
        LOGGER.exception(
            "Job %s: failed to persist result step=%s command=%s",
            job_id,
            result.get("step_order"),
            result.get("command"),
        )
        return False


async def run_job(pool: asyncpg.Pool, config: Config, job: AppJob) -> Dict[str, Any]:
    LOGGER.info(
        "Job %s: starting run (playbook=%s server=%s sudo=%s)",
        job.id,
        job.playbook_id,
        job.server_id,
        job.use_sudo,
    )
    async with JobEventStream(config, job.id) as event_stream:
        context: Optional[Dict[str, Any]] = None
        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE jobs
                SET status = 'running', started_at = COALESCE(started_at, NOW())
                WHERE id = $1
                """,
                job.id,
            )
            await event_stream.emit(
                "job.running",
                {
                    "jobId": job.id,
                    "playbookId": job.playbook_id,
                    "serverId": job.server_id,
                    "useSudo": job.use_sudo,
                },
            )
            try:
                LOGGER.info("Job %s: loading job context", job.id)
                context = await get_job_context(conn, job)
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Job %s failed during context load: %s", job.id, exc)
                failure_result = build_failure_job_result(
                    step_order=0,
                    command="__prepare__",
                    status="failed",
                    message=f"{type(exc).__name__}: {exc}",
                )
                await safe_insert_job_result(conn, job.id, failure_result)
                await conn.execute(
                    """
                    UPDATE jobs
                    SET status = 'failed', completed_at = NOW()
                    WHERE id = $1
                    """,
                    job.id,
                )
                await event_stream.emit(
                    "job.completed",
                    {
                        "jobId": job.id,
                        "status": "failed",
                        "metrics": {},
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                )

                return {
                    "job_id": job.id,
                    "status": "failed",
                    "metrics": {},
                }

        if context is None:
            await event_stream.emit(
                "job.completed",
                {
                    "jobId": job.id,
                    "status": "failed",
                    "metrics": {},
                    "error": "job context unavailable",
                },
            )
            return {
                "job_id": job.id,
                "status": "failed",
                "metrics": {},
            }

        credential = context["credential"]
        server_username = context["server"]["username"]
        secret = decrypt_secret(str(credential["encrypted_value"]), config.encryption_key)
        resolved_username = resolve_ssh_username(
            str(server_username) if server_username is not None else None, str(credential["username"])
        )

        connect_kwargs: Dict[str, Any] = {
            "host": str(context["server"]["ip_address"]),
            "port": int(context["server"]["port"]),
            "username": resolved_username,
            "known_hosts": None,
        }
        LOGGER.info(
            "Job %s: context ready server=%s host=%s:%s username=%s credential=%s type=%s steps=%s",
            job.id,
            context["server"]["hostname"],
            context["server"]["ip_address"],
            context["server"]["port"],
            resolved_username,
            context["credential"]["id"],
            context["credential"]["type"],
            len(context["steps"]),
        )
        await event_stream.emit(
            "job.context_ready",
            {
                "jobId": job.id,
                "server": {
                    "id": str(context["server"]["id"]),
                    "hostname": str(context["server"]["hostname"]),
                    "ipAddress": str(context["server"]["ip_address"]),
                    "port": int(context["server"]["port"]),
                    "username": resolved_username,
                },
                "stepCount": len(context["steps"]),
            },
        )

        if credential["type"] == "password":
            connect_kwargs["password"] = secret
        else:
            connect_kwargs["client_keys"] = [asyncssh.import_private_key(secret)]

        status = "success"
        metrics: Dict[str, float] = {}
        failure_result: Optional[Dict[str, Any]] = None
        current_step_order = 0
        current_step_command = "__connect__"

        async def run_steps(ssh_conn: asyncssh.SSHClientConnection) -> None:
            nonlocal status, current_step_order, current_step_command

            LOGGER.info("Job %s: SSH connection established", job.id)
            await event_stream.emit("ssh.connected", {"jobId": job.id})
            for step in context["steps"]:
                order = int(step["order"])
                command = _apply_sudo(str(step["command"]), job.use_sudo)
                current_step_order = order
                current_step_command = command
                expected_exit_code = int(step["expected_exit_code"])
                parse_rule = step["parse_rule"] or {}
                parse_kind = parse_rule.get("kind", "raw") if isinstance(parse_rule, dict) else "raw"
                LOGGER.info(
                    "Job %s: executing step=%s expected_exit=%s command=%s",
                    job.id,
                    order,
                    expected_exit_code,
                    command,
                )
                await event_stream.emit(
                    "step.started",
                    {
                        "jobId": job.id,
                        "stepOrder": order,
                        "command": command,
                        "expectedExitCode": expected_exit_code,
                    },
                )

                started = asyncio.get_running_loop().time()
                result = await execute_step(ssh_conn, command, config.command_timeout_s)
                duration_ms = int((asyncio.get_running_loop().time() - started) * 1000)
                LOGGER.info(
                    "Job %s: step=%s completed exit=%s duration_ms=%s",
                    job.id,
                    order,
                    result["exit_code"],
                    duration_ms,
                )

                parsed_values = parse_output(str(parse_kind), str(result["stdout"]))

                if "disk_percent" in parsed_values:
                    metrics["disk_percent"] = float(parsed_values["disk_percent"])
                if "memory_percent" in parsed_values:
                    metrics["memory_percent"] = float(parsed_values["memory_percent"])

                async with pool.acquire() as conn:
                    await safe_insert_job_result(
                        conn,
                        job.id,
                        {
                            "step_order": order,
                            "command": command,
                            "exit_code": result["exit_code"],
                            "stdout": result["stdout"],
                            "stderr": result["stderr"],
                            "duration_ms": duration_ms,
                            "parsed_values": parsed_values,
                        },
                    )

                await event_stream.emit(
                    "step.completed",
                    {
                        "jobId": job.id,
                        "stepOrder": order,
                        "command": command,
                        "exitCode": int(result["exit_code"]),
                        "stdout": str(result["stdout"]),
                        "stderr": str(result["stderr"]),
                        "durationMs": duration_ms,
                        "parsedValues": parsed_values,
                    },
                )

                if int(result["exit_code"]) != expected_exit_code:
                    LOGGER.warning(
                        "Job %s: step=%s exit mismatch expected=%s actual=%s",
                        job.id,
                        order,
                        expected_exit_code,
                        result["exit_code"],
                    )
                    await event_stream.emit(
                        "step.exit_mismatch",
                        {
                            "jobId": job.id,
                            "stepOrder": order,
                            "expectedExitCode": expected_exit_code,
                            "actualExitCode": int(result["exit_code"]),
                        },
                    )
                    status = "failed"
                    break

        try:
            LOGGER.info(
                "Job %s: opening SSH connection to %s:%s as %s",
                job.id,
                connect_kwargs["host"],
                connect_kwargs["port"],
                connect_kwargs["username"],
            )
            try:
                async with asyncssh.connect(**connect_kwargs) as ssh_conn:
                    await run_steps(ssh_conn)
            except OSError as exc:
                if exc.errno != 65:
                    raise

                nc_path = shutil.which("nc")
                if not nc_path:
                    raise

                host = str(connect_kwargs["host"])
                port = int(connect_kwargs["port"])
                proxy_command = f"{shlex.quote(nc_path)} {shlex.quote(host)} {port}"
                LOGGER.warning(
                    "Job %s: direct SSH connect failed with errno=%s; retrying via proxy_command=%s",
                    job.id,
                    exc.errno,
                    proxy_command,
                )
                await event_stream.emit(
                    "ssh.retry_with_proxy",
                    {
                        "jobId": job.id,
                        "proxyCommand": proxy_command,
                        "errno": int(exc.errno) if exc.errno is not None else None,
                    },
                )
                retry_kwargs = {**connect_kwargs, "proxy_command": proxy_command}
                async with asyncssh.connect(**retry_kwargs) as ssh_conn:
                    await run_steps(ssh_conn)

        except asyncio.TimeoutError:
            status = "timeout"
            failure_result = build_failure_job_result(
                step_order=current_step_order,
                command=current_step_command,
                status=status,
                message=f"Command timed out after {config.command_timeout_s} seconds.",
            )
            LOGGER.error("Job %s: command timeout while executing %s", job.id, current_step_command)
            await event_stream.emit(
                "step.timeout",
                {
                    "jobId": job.id,
                    "stepOrder": current_step_order,
                    "command": current_step_command,
                    "timeoutSeconds": config.command_timeout_s,
                },
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Job %s failed: %s", job.id, exc)
            status = "failed"
            failure_result = build_failure_job_result(
                step_order=current_step_order,
                command=current_step_command,
                status=status,
                message=f"{type(exc).__name__}: {exc}",
            )
            await event_stream.emit(
                "step.error",
                {
                    "jobId": job.id,
                    "stepOrder": current_step_order,
                    "command": current_step_command,
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )

        async with pool.acquire() as conn:
            if failure_result:
                await safe_insert_job_result(conn, job.id, failure_result)

            await conn.execute(
                """
                UPDATE jobs
                SET status = $2, completed_at = NOW()
                WHERE id = $1
                """,
                job.id,
                status,
            )
            alerts_via_api = await evaluate_alerts_via_api(config, job.id, job.server_id, metrics)
            if not alerts_via_api:
                await evaluate_alerts(conn, job.server_id, metrics)
            LOGGER.info("Job %s: completed with status=%s metrics=%s", job.id, status, metrics)

        await event_stream.emit(
            "job.completed",
            {
                "jobId": job.id,
                "status": status,
                "metrics": metrics,
            },
        )

        return {
            "job_id": job.id,
            "status": status,
            "metrics": metrics,
        }


async def _wait_for_pgboss_schema(pool: asyncpg.Pool, schema: str, timeout: float = 120) -> None:
    """Wait for the pgboss schema to be created by the API service."""
    safe_schema = _safe_identifier(schema)
    deadline = asyncio.get_event_loop().time() + timeout
    delay = 2
    while True:
        try:
            async with pool.acquire() as conn:
                exists = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'job')",
                    schema,
                )
            if exists:
                LOGGER.info("pgboss schema %s is ready", schema)
                return
        except Exception:  # noqa: BLE001
            pass

        if asyncio.get_event_loop().time() >= deadline:
            raise RuntimeError(
                f"Timed out waiting for {safe_schema}.job table. "
                "Ensure the API service has started and initialized the database."
            )

        LOGGER.info("Waiting for %s.job table to be created by the API... retrying in %ds", safe_schema, delay)
        await asyncio.sleep(delay)
        delay = min(delay * 2, 15)


async def worker_loop(config: Config) -> None:
    pool = await asyncpg.create_pool(dsn=config.database_url, min_size=1, max_size=config.worker_concurrency)
    semaphore = asyncio.Semaphore(config.worker_concurrency)

    await _wait_for_pgboss_schema(pool, config.pgboss_schema)

    async def process(claim: QueueClaim) -> None:
        async with semaphore:
            LOGGER.info("Claimed queue job=%s app_job=%s", claim.queue_job_id, claim.app_job_id)
            async with pool.acquire() as conn:
                app_job = await get_app_job(conn, claim.app_job_id)

            if not app_job:
                async with pool.acquire() as conn:
                    await mark_queue_job_failed(
                        conn,
                        schema=config.pgboss_schema,
                        queue_name=config.pgboss_queue,
                        queue_job_id=claim.queue_job_id,
                        output={"error": f"job {claim.app_job_id} not found"},
                    )
                LOGGER.error("Queue job=%s references missing app job=%s", claim.queue_job_id, claim.app_job_id)
                return

            try:
                result = await run_job(pool, config, app_job)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Queue job=%s app_job=%s crashed before completion", claim.queue_job_id, app_job.id)
                async with pool.acquire() as conn:
                    await mark_queue_job_failed(
                        conn,
                        schema=config.pgboss_schema,
                        queue_name=config.pgboss_queue,
                        queue_job_id=claim.queue_job_id,
                        output={"job_id": app_job.id, "status": "failed", "error": "worker crash"},
                    )
                return

            async with pool.acquire() as conn:
                if result["status"] == "success":
                    await mark_queue_job_completed(
                        conn,
                        schema=config.pgboss_schema,
                        queue_name=config.pgboss_queue,
                        queue_job_id=claim.queue_job_id,
                        output=result,
                    )
                else:
                    await mark_queue_job_failed(
                        conn,
                        schema=config.pgboss_schema,
                        queue_name=config.pgboss_queue,
                        queue_job_id=claim.queue_job_id,
                        output=result,
                    )
            LOGGER.info(
                "Queue job=%s app_job=%s finalized with status=%s",
                claim.queue_job_id,
                app_job.id,
                result["status"],
            )

    async def process_rotation(raw_claim: QueueClaim, payload: Dict[str, Any]) -> None:
        async with semaphore:
            LOGGER.info("Claimed rotation job=%s", raw_claim.queue_job_id)
            rotation_job = RotationJob(
                rotation_history_id=str(payload["rotationHistoryId"]),
                credential_id=str(payload["credentialId"]),
                encrypted_new_private_key=str(payload["encryptedNewPrivateKey"]),
                new_public_key_pem=str(payload["newPublicKeyPem"]),
            )
            try:
                await run_rotation_job(pool, config, rotation_job)
                async with pool.acquire() as conn:
                    await mark_queue_job_completed(
                        conn,
                        schema=config.pgboss_schema,
                        queue_name=config.credential_rotation_queue,
                        queue_job_id=raw_claim.queue_job_id,
                        output={"rotationHistoryId": rotation_job.rotation_history_id, "status": "success"},
                    )
            except Exception:  # noqa: BLE001
                LOGGER.exception("Rotation job=%s crashed", raw_claim.queue_job_id)
                async with pool.acquire() as conn:
                    await mark_queue_job_failed(
                        conn,
                        schema=config.pgboss_schema,
                        queue_name=config.credential_rotation_queue,
                        queue_job_id=raw_claim.queue_job_id,
                        output={"rotationHistoryId": rotation_job.rotation_history_id, "status": "failed"},
                    )

    try:
        tasks: List[asyncio.Task[None]] = []
        while True:
            claimed_any = False

            async with pool.acquire() as conn:
                async with conn.transaction():
                    claim = await claim_queue_job(conn, config.pgboss_schema, config.pgboss_queue)

            if claim:
                claimed_any = True
                tasks = [task for task in tasks if not task.done()]
                tasks.append(asyncio.create_task(process(claim)))

            # Poll rotation queue
            async with pool.acquire() as conn:
                async with conn.transaction():
                    rotation_row = await conn.fetchrow(
                        f"""
                        WITH next AS (
                          SELECT id
                          FROM {config.pgboss_schema}.job
                          WHERE name = $1
                            AND state < 'active'
                            AND start_after < now()
                          ORDER BY priority DESC, created_on, id
                          LIMIT 1
                          FOR UPDATE SKIP LOCKED
                        )
                        UPDATE {config.pgboss_schema}.job j
                        SET state = 'active',
                            started_on = now(),
                            retry_count = CASE WHEN started_on IS NOT NULL THEN retry_count + 1 ELSE retry_count END
                        FROM next
                        WHERE j.id = next.id
                        RETURNING j.id, j.data
                        """,
                        config.credential_rotation_queue,
                    )

            if rotation_row:
                claimed_any = True
                raw_payload = rotation_row["data"] or {}
                if isinstance(raw_payload, str):
                    raw_payload = json.loads(raw_payload)
                rotation_claim = QueueClaim(
                    queue_job_id=str(rotation_row["id"]),
                    app_job_id=str(raw_payload.get("rotationHistoryId", "")),
                )
                tasks = [task for task in tasks if not task.done()]
                tasks.append(asyncio.create_task(process_rotation(rotation_claim, raw_payload)))

            if not claimed_any:
                await asyncio.sleep(config.poll_interval_ms / 1000)

    finally:
        await pool.close()


def cli() -> None:
    load_dotenv()
    config = load_config()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    LOGGER.info("starting aviary worker")
    asyncio.run(worker_loop(config))
