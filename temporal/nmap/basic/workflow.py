import asyncio
import uuid
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from logging import getLogger
from typing import Any

from temporalio import workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy

from config import AppConfig
from temporal.nmap.basic.activities import NmapBasicActivities


@workflow.defn(name="NmapBasicWorkflow")
class NmapBasicWorkflow:
    """
    Workflow that runs a basic nmap scan, parses the XML, and publishes results to ISIM.
    """

    @workflow.run
    async def run(self, input_: dict[str, Any] | None = None) -> None:
        """
        Execute the basic nmap workflow end-to-end.

        :param input_: Optional mapping compatible with NmapBasicConfig to override defaults.
        :return: None
        """
        config = AppConfig.get()
        nmap_config = config.nmap_basic

        if input_ is not None:
            nmap_config = await workflow.execute_activity(
                NmapBasicActivities.nmap_basic_validate_input,
                arg=input_,
                retry_policy=RetryPolicy(maximum_attempts=1),
                start_to_close_timeout=timedelta(minutes=5),
            )

        nmap_results = await workflow.execute_activity(
            NmapBasicActivities.run_basic_nmap_scan,
            args=[nmap_config.targets, nmap_config.arguments],
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "NmapExecutionError"],
            ),
            start_to_close_timeout=timedelta(minutes=5),
        )

        parsed_nmap_results = await workflow.execute_activity(
            NmapBasicActivities.parse_nmap_xml,
            args=[nmap_results, nmap_config.tag],
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
            NmapBasicActivities.send_result_to_api,
            parsed_nmap_results,
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
        Collect all activity callables used by the basic nmap workflow.

        :return: A flat sequence of activity functions to be registered with a worker.
        """
        config = AppConfig.get()
        activities = NmapBasicActivities(config.isim)
        return [*activities.get_activities()]


async def main() -> None:
    """
    Convenience entry point to start the NmapBasicWorkflow from the CLI.

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
        NmapBasicWorkflow.run,
        args=(),
        id=workflow_id,
        task_queue=config.temporal.nmap_task_queue,
        id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE,
    )
    workflow_description = await workflow_handle.describe()
    logger.info("Workflow start requested.", workflow_id=workflow_description.id, run_id=workflow_description.run_id)


if __name__ == "__main__":
    asyncio.run(main())
