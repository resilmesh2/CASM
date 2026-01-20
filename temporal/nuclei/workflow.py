import asyncio
import uuid
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from logging import getLogger
from typing import Any

from structlog import getLogger
from temporalio.client import Client
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy

from config import AppConfig
from temporal.nuclei.activities import NucleiActivities
from temporalio import workflow


@workflow.defn(name="NucleiWorkflow")
class NucleiWorkflow:
    """
    Workflow that runs a nuclei scan for each network service and updates the vulnerability status in neo4j.
    """

    @workflow.run
    async def run(self) -> None:
        await workflow.execute_activity(
            NucleiActivities.update_nuclei,
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "NmapExecutionError"],
            ),
            start_to_close_timeout=timedelta(minutes=5),
        )

        network_service_data_uuid = await workflow.execute_activity(
            NucleiActivities.get_network_service_data,
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "NmapExecutionError"],
            ),
            start_to_close_timeout=timedelta(minutes=5),
        )

        service_data_for_nuclei_uuid = await workflow.execute_activity(
            NucleiActivities.parse_network_service_data_for_nuclei_run,
            network_service_data_uuid,
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError"],
            ),
            start_to_close_timeout=timedelta(minutes=5),
        )

        cves_status_uuid = await workflow.execute_activity(
            NucleiActivities.run_nuclei,
            service_data_for_nuclei_uuid,
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError"],
            ),
            start_to_close_timeout=timedelta(minutes=5),
        )

        await workflow.execute_activity(
            NucleiActivities.update_cve_lifecycle_info,
            cves_status_uuid,
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError"],
            ),
            start_to_close_timeout=timedelta(minutes=5),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        """
        Collect all activity callables used by nuclei workflow.

        :return: A flat sequence of activity functions to be registered with a worker.
        """
        config = AppConfig.get()
        activities = NucleiActivities(config.isim_urls, config.isim_urls, config.redis, config.neo4j)
        return [*activities.get_activities()]


async def main() -> None:
    """
    Convenience entry point to start the NucleiWorkflow from the CLI.

    Connects to the Temporal server, starts a workflow run on the configured task
    queue, and logs basic information about the request.

    :return: None
    """
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    logger = getLogger()
    workflow_id = uuid.uuid4().hex
    # noinspection PyTypeChecker
    workflow_handle = await client.start_workflow(
        NucleiWorkflow.run,
        args=(),
        id=workflow_id,
        task_queue=config.temporal.scanning_task_queue,
        id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE,
    )
    workflow_description = await workflow_handle.describe()
    logger.info("Workflow start requested.", workflow_id=workflow_description.id, run_id=workflow_description.run_id)


if __name__ == "__main__":
    asyncio.run(main())
