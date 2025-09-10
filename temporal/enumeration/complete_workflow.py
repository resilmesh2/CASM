import asyncio
import uuid
from collections.abc import Awaitable, Callable, Sequence
from logging import getLogger
from typing import Any

from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy

from config import AppConfig
from temporal.enumeration.active_enumeration.activities import ActiveEnumerationActivities
from temporal.enumeration.active_enumeration.workflow import ActiveEnumeratonWorkflow
from temporal.enumeration.passive_enumeration.activities import PassiveEnumerationActivities
from temporal.enumeration.passive_enumeration.workflow import PassiveEnumerationWorkflow
from temporal.enumeration.ulitity_activities import UtilityActivities
from temporalio import workflow


@workflow.defn
class CompleteScanWorkflow:
    @workflow.run
    async def run(self) -> str:
        config = AppConfig.get()
        passive_result_uuid = await workflow.execute_child_workflow(
            PassiveEnumerationWorkflow.run,
            args=[config.scanner.domains],
            id=f"passive-{workflow.info().workflow_id}",
            task_queue=config.temporal.easyeasm_task_queue,
        )

        # 2) Active
        active_result: str = await workflow.execute_child_workflow(
            ActiveEnumeratonWorkflow.run,
            args=[passive_result_uuid, config.scanner.wordlist],
            id=f"active-{workflow.info().workflow_id}",
            task_queue=config.temporal.easyeasm_task_queue,
        )

        return active_result

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        passive_enum_activities = PassiveEnumerationActivities(config.redis)
        active_enum_activities = ActiveEnumerationActivities(config.redis)
        utility_activities = UtilityActivities(config.redis)
        return [*passive_enum_activities.get_activities(), *active_enum_activities.get_activities(), utility_activities.get_unique_subdomains]


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    logger = getLogger()
    workflow_id = uuid.uuid4().hex
    # noinspection PyTypeChecker
    workflow_handle = await client.start_workflow(
        CompleteScanWorkflow.run,
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
