from __future__ import annotations

import asyncio
import os
import shlex
from datetime import UTC, datetime, timedelta

from temporalio.client import Client
from temporalio.exceptions import TemporalError

from test.e2e.temporal_checks import connect_temporal, trigger_schedule, wait_for_workflow_type

TEMPORAL_ADDRESS = os.getenv("E2E_TEMPORAL_ADDRESS", "localhost:7233")
TEMPORAL_NAMESPACE = os.getenv("E2E_TEMPORAL_NAMESPACE", "default")

SHARED_WORKER = os.getenv("E2E_SHARED_WORKER", "resilmesh-sap-casm-shared-worker")
EASM_WORKER = os.getenv("E2E_EASM_WORKER", "resilmesh-sap-casm-easm-worker")
CVE_WORKER = os.getenv("E2E_CVE_WORKER", "resilmesh-sap-casm-cve-connector")

CVE_SCHEDULE_ID = "cve-update-scheduled-workflow"
COMPONENT_SCHEDULE_IDS = [
    "component-schedule-criticality",
    "component-schedule-threatScore",
    "component-schedule-cvss_score",
]
RISK_FORMULA_SCHEDULE_ID = "automation-schedule-base-risk"


def _timeout(name: str, default_seconds: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default_seconds
    try:
        return int(raw)
    except ValueError:
        return default_seconds


async def _connect_with_retry(address: str, namespace: str, timeout_seconds: int = 300) -> Client:
    deadline = datetime.now(tz=UTC) + timedelta(seconds=timeout_seconds)
    last_error: Exception | None = None
    while datetime.now(tz=UTC) < deadline:
        try:
            return await connect_temporal(address, namespace)
        except TemporalError as exc:
            last_error = exc
        except ConnectionError as exc:  # pragma: no cover - environment dependent
            last_error = exc
        await asyncio.sleep(5)
    msg = f"Timed out connecting to Temporal at {address} (namespace={namespace}). Last error: {last_error}"
    raise TimeoutError(msg)


async def run_docker_module(container: str, module: str) -> None:
    cmd = ["docker", "exec", container, "python", "-m", module]
    print(f"\n[exec] {shlex.join(cmd)}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    stdout, _ = await proc.communicate()
    output = (stdout or b"").decode(errors="replace")
    if proc.returncode != 0:
        tail = "\n".join(output.strip().splitlines()[-50:])
        msg = f"Command failed ({proc.returncode}): {shlex.join(cmd)}\n--- output tail ---\n{tail}"
        raise RuntimeError(msg)
    if output.strip():
        tail = "\n".join(output.strip().splitlines()[-20:])
        print(f"[exec:tail]\n{tail}")


async def stage_nmap(client: Client) -> None:
    print("\n== Stage 1: Nmap (basic + topology in parallel) ==")
    started_after = datetime.now(tz=UTC)
    await asyncio.gather(
        run_docker_module(SHARED_WORKER, "temporal.nmap.basic.workflow"),
        run_docker_module(SHARED_WORKER, "temporal.nmap.topology.workflow"),
    )
    await wait_for_workflow_type(
        client,
        "NmapBasicWorkflow",
        started_after,
        timeout=_timeout("E2E_NMAP_TIMEOUT_SECONDS", 1800),
    )
    await wait_for_workflow_type(
        client,
        "NmapTopologyWorkflow",
        started_after,
        timeout=_timeout("E2E_NMAP_TIMEOUT_SECONDS", 1800),
    )


async def stage_easm(client: Client) -> None:
    print("\n== Stage 2: EASM parent workflow ==")
    started_after = datetime.now(tz=UTC)
    await run_docker_module(EASM_WORKER, "temporal.easm.parent_workflow")
    await wait_for_workflow_type(
        client,
        "ParentEasmWorkflow",
        started_after,
        timeout=_timeout("E2E_EASM_TIMEOUT_SECONDS", 3600),
    )


async def stage_cve(client: Client) -> None:
    print("\n== Stage 3: CVE connector schedule trigger ==")
    # CVE connector runs as a worker/scheduler container. We trigger its schedule explicitly.
    started_after = datetime.now(tz=UTC)
    print(f"[schedule:trigger] {CVE_SCHEDULE_ID}")
    await trigger_schedule(client, CVE_SCHEDULE_ID, timeout=_timeout("E2E_SCHEDULE_TIMEOUT_SECONDS", 600))
    await wait_for_workflow_type(
        client,
        "CveUpdateWorkflow",
        started_after,
        timeout=_timeout("E2E_CVE_TIMEOUT_SECONDS", 2700),
    )


async def stage_nuclei(client: Client) -> None:
    print("\n== Stage 4: Nuclei workflow ==")
    started_after = datetime.now(tz=UTC)
    await run_docker_module(SHARED_WORKER, "temporal.nuclei.workflow")
    await wait_for_workflow_type(
        client,
        "NucleiWorkflow",
        started_after,
        timeout=_timeout("E2E_NUCLEI_TIMEOUT_SECONDS", 1800),
    )


async def stage_components(client: Client) -> None:
    print("\n== Stage 5: Component schedules (score + risk formula) ==")
    started_after = datetime.now(tz=UTC)
    for schedule_id in COMPONENT_SCHEDULE_IDS:
        print(f"[schedule:trigger] {schedule_id}")
        await trigger_schedule(client, schedule_id, timeout=_timeout("E2E_SCHEDULE_TIMEOUT_SECONDS", 600))
    print(f"[schedule:trigger] {RISK_FORMULA_SCHEDULE_ID}")
    await trigger_schedule(client, RISK_FORMULA_SCHEDULE_ID, timeout=_timeout("E2E_SCHEDULE_TIMEOUT_SECONDS", 600))

    await wait_for_workflow_type(
        client,
        "ComponentScoreCalculationWorkflow",
        started_after,
        min_completed=3,
        timeout=_timeout("E2E_COMPONENT_TIMEOUT_SECONDS", 1800),
    )
    await wait_for_workflow_type(
        client,
        "RiskFormulaCalculationWorkflow",
        started_after,
        timeout=_timeout("E2E_COMPONENT_TIMEOUT_SECONDS", 1800),
    )


async def main() -> None:
    print(
        "Starting E2E workflow orchestration with:\n"
        f"- Temporal: {TEMPORAL_ADDRESS} (ns={TEMPORAL_NAMESPACE})\n"
        f"- Shared worker: {SHARED_WORKER}\n"
        f"- EASM worker: {EASM_WORKER}\n"
        f"- CVE worker: {CVE_WORKER}"
    )

    client = await _connect_with_retry(
        TEMPORAL_ADDRESS,
        TEMPORAL_NAMESPACE,
        timeout_seconds=_timeout("E2E_TEMPORAL_CONNECT_TIMEOUT_SECONDS", 300),
    )

    await stage_nmap(client)
    await stage_easm(client)
    await stage_cve(client)
    await stage_nuclei(client)
    await stage_components(client)

    print("\nE2E orchestration finished successfully.")


if __name__ == "__main__":
    asyncio.run(main())
