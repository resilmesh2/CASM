import asyncio
import uuid
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from logging import getLogger
from typing import Any

from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy

from config import AppConfig
from temporal.nmap.basic.activities import NmapBasicActivities
from temporalio import workflow


@workflow.defn(name="NmapBasicWorkflow")
class NmapBasicWorkflow:
    @workflow.run
    async def run(self) -> None:
        nmap_results = await workflow.execute_activity(
            NmapBasicActivities.run_nmap_scan,
            start_to_close_timeout=timedelta(minutes=5),
        )

        parsed_nmap_results = await workflow.execute_activity(
            NmapBasicActivities.parse_nmap_xml,
            nmap_results,
            start_to_close_timeout=timedelta(minutes=5),
        )

        await workflow.execute_activity(
            NmapBasicActivities.send_result_to_api,
            parsed_nmap_results,
            start_to_close_timeout=timedelta(minutes=5),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = NmapBasicActivities(config.nmap_basic, config.isim)
        return [*activities.get_activities()]


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    logger = getLogger()
    workflow_id = uuid.uuid4().hex
    # noinspection PyTypeChecker
    workflow_handle = await client.start_workflow(
        NmapBasicWorkflow.run,
        args=(),
        id=workflow_id,
        task_queue=config.temporal.nmap_task_queue,
        id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE,
    )
    workflow_description = await workflow_handle.describe()
    logger.info(
        "Workflow start requested.", workflow_id=workflow_description.id, run_id=workflow_description.run_id
    )


if __name__ == "__main__":
    asyncio.run(main())
