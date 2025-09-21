import asyncio
import uuid
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from structlog import getLogger
from temporalio.client import Client
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy

from config import AppConfig
from temporal.nmap.topology.activities import NmapTopologyActivities
from temporalio import workflow


@workflow.defn(name="NmapTopologyWorkflow")
class NmapTopologyWorkflow:
    @workflow.run
    async def run(self, input_: dict[str, Any] | None = None) -> None:
        config = AppConfig.get()
        nmap_config = config.nmap_topology

        if input_ is not None:
            nmap_config = await workflow.execute_activity(
                NmapTopologyActivities.nmap_topology_validate_input,
                arg=input_,
                retry_policy=RetryPolicy(maximum_attempts=1),
                start_to_close_timeout=timedelta(minutes=5),
            )

        nmap_results = await workflow.execute_activity(
            NmapTopologyActivities.run_nmap_traceroute_scan,
            args=[nmap_config.targets],
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "NmapExecutionError"],
            ),
            start_to_close_timeout=timedelta(minutes=60),
        )

        await workflow.execute_activity(
            NmapTopologyActivities.nmap_traceroute_neo4j,
            nmap_results,
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError"],
            ),
            start_to_close_timeout=timedelta(minutes=60),
        )

        await workflow.execute_activity(
            NmapTopologyActivities.compute_criticalities,
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError"],
            ),
            start_to_close_timeout=timedelta(minutes=60),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = NmapTopologyActivities(config.isim)
        return [*activities.get_activities()]


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    logger = getLogger()
    workflow_id = uuid.uuid4().hex
    # noinspection PyTypeChecker
    workflow_handle = await client.start_workflow(
        NmapTopologyWorkflow.run,
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
