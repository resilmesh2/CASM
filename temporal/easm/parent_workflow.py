import asyncio
import uuid
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from logging import getLogger
from typing import Any

from temporalio.client import Client
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy

from config import AppConfig
from temporal.easm.active_enumeration.activities import ActiveEnumerationActivities
from temporal.easm.active_enumeration.workflow import ActiveEnumeratonWorkflow
from temporal.easm.activities import EasmActivities
from temporal.easm.passive_enumeration.activities import PassiveEnumerationActivities
from temporal.easm.passive_enumeration.workflow import PassiveEnumerationWorkflow
from temporalio import workflow


@workflow.defn
class ParentEasmWorkflow:
    @workflow.run
    async def run(self) -> str:
        config = AppConfig.get()
        domains_output_uuid = await workflow.execute_child_workflow(
            PassiveEnumerationWorkflow.run,
            args=[config.easm_scanner.domains],
            id=f"passive-{workflow.info().workflow_id}",
            task_queue=config.temporal.easyeasm_task_queue,
        )

        if config.easm_scanner.complete:
            domains_output_uuid: str = await workflow.execute_child_workflow(
                ActiveEnumeratonWorkflow.run,
                args=[domains_output_uuid, config.easm_scanner.wordlist_path, str(config.easm_scanner.threads)],
                id=f"active-{workflow.info().workflow_id}",
                task_queue=config.temporal.easyeasm_task_queue,
            )

        httpx_uuid = await workflow.execute_activity(
            EasmActivities.run_httpx,
            args=[domains_output_uuid, config.easm_scanner.httpx_path],
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=2,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "EnumerationToolError"],
            ),
            start_to_close_timeout=timedelta(minutes=60),
        )

        return await workflow.execute_activity(
            EasmActivities.parse_result_and_send_to_api,
            args=[httpx_uuid],
            start_to_close_timeout=timedelta(minutes=5),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        passive_enum_activities = PassiveEnumerationActivities(config.redis)
        active_enum_activities = ActiveEnumerationActivities(config.redis)
        activities = EasmActivities(config.redis, config.isim)
        return [*passive_enum_activities.get_activities(), *active_enum_activities.get_activities(), *activities.get_activities()]


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    logger = getLogger()
    workflow_id = uuid.uuid4().hex
    # noinspection PyTypeChecker
    workflow_handle = await client.start_workflow(
        ParentEasmWorkflow.run,
        args=(),
        id=workflow_id,
        task_queue=config.temporal.easyeasm_task_queue,
        id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE,
    )
    workflow_description = await workflow_handle.describe()
    logger.info(
        "Workflow start requested.", workflow_id=workflow_description.id, run_id=workflow_description.run_id
    )


if __name__ == "__main__":
    asyncio.run(main())
