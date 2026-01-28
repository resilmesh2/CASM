from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable

from temporalio.api.enums.v1 import WorkflowExecutionStatus
from temporalio.client import Client
from temporalio.exceptions import TemporalError

COMPLETED = WorkflowExecutionStatus.WORKFLOW_EXECUTION_STATUS_COMPLETED
FAILED = {
    WorkflowExecutionStatus.WORKFLOW_EXECUTION_STATUS_FAILED,
    WorkflowExecutionStatus.WORKFLOW_EXECUTION_STATUS_TIMED_OUT,
    WorkflowExecutionStatus.WORKFLOW_EXECUTION_STATUS_TERMINATED,
    WorkflowExecutionStatus.WORKFLOW_EXECUTION_STATUS_CANCELED,
}


async def _maybe_await(value: Any) -> Any:
    """Compatibility helper for SDK methods that may be awaitable in some versions."""
    if inspect.isawaitable(value):
        return await value
    return value


async def connect_temporal(address: str, namespace: str) -> Client:
    """Connect to Temporal with explicit namespace selection."""
    return await Client.connect(address, namespace=namespace)


async def schedule_exists(client: Client, schedule_id: str) -> bool:
    iterator = await _maybe_await(client.list_schedules())
    async for item in iterator:
        if item.id == schedule_id:
            return True
    return False


async def wait_for_schedule(client: Client, schedule_id: str, timeout: int = 600) -> None:
    """Wait until a schedule appears in Temporal visibility."""
    deadline = datetime.now(tz=UTC) + timedelta(seconds=timeout)
    while datetime.now(tz=UTC) < deadline:
        if await schedule_exists(client, schedule_id):
            return
        await asyncio.sleep(5)
    msg = f"Timed out waiting for schedule '{schedule_id}' to be created."
    raise TimeoutError(msg)


async def trigger_schedule(client: Client, schedule_id: str, timeout: int = 600) -> None:
    """Trigger a schedule immediately, waiting for it to exist first."""
    await wait_for_schedule(client, schedule_id, timeout=timeout)
    handle = client.get_schedule_handle(schedule_id)
    await handle.trigger()


@dataclass(frozen=True)
class WorkflowSummary:
    workflow_id: str
    run_id: str
    status: WorkflowExecutionStatus
    start_time: datetime


async def list_workflows_of_type(client: Client, workflow_type: str) -> list[WorkflowSummary]:
    """List all visible workflows of a given type."""
    query = f"WorkflowType = '{workflow_type}'"
    iterator = await _maybe_await(client.list_workflows(query))
    results: list[WorkflowSummary] = []
    async for execution in iterator:
        results.append(
            WorkflowSummary(
                workflow_id=execution.id,
                run_id=execution.run_id,
                status=execution.status,
                start_time=execution.start_time,
            )
        )
    return results


def _recent(executions: Iterable[WorkflowSummary], started_after: datetime, slack_seconds: int = 30) -> list[WorkflowSummary]:
    cutoff = started_after - timedelta(seconds=slack_seconds)
    return [e for e in executions if e.start_time >= cutoff]


async def wait_for_workflow_type(
    client: Client,
    workflow_type: str,
    started_after: datetime,
    *,
    min_completed: int = 1,
    timeout: int = 1800,
    poll_interval: int = 5,
) -> list[WorkflowSummary]:
    """
    Wait for at least `min_completed` workflows of `workflow_type` started after the given time.

    Raises on failed terminal states.
    """
    deadline = datetime.now(tz=UTC) + timedelta(seconds=timeout)
    last_seen: list[WorkflowSummary] = []

    while datetime.now(tz=UTC) < deadline:
        try:
            workflows = await list_workflows_of_type(client, workflow_type)
        except TemporalError as exc:  # Visibility may not be ready yet.
            last_seen = []
            await asyncio.sleep(poll_interval)
            continue

        recent = _recent(workflows, started_after)
        last_seen = recent

        if not recent:
            await asyncio.sleep(poll_interval)
            continue

        completed = [wf for wf in recent if wf.status == COMPLETED]
        failed = [wf for wf in recent if wf.status in FAILED]

        if failed:
            details = ", ".join(f"{wf.workflow_id}:{wf.status.name}" for wf in failed)
            msg = f"Workflow type '{workflow_type}' had failed executions: {details}"
            raise RuntimeError(msg)

        if len(completed) >= min_completed:
            return completed

        await asyncio.sleep(poll_interval)

    details = ", ".join(f"{wf.workflow_id}:{wf.status.name}" for wf in last_seen) or "none"
    msg = (
        f"Timed out waiting for workflow type '{workflow_type}' to complete. "
        f"Recent executions: {details}"
    )
    raise TimeoutError(msg)
