from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from temporalio.common import RetryPolicy

from config import AppConfig
from temporal.nuclei.activities import NucleiActivities
from temporalio import workflow


@workflow.defn(name="NucleiWorkflow")
class NucleiWorkflow:
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

        cves_status = await workflow.execute_activity(
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
            cves_status,
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
        activities = NucleiActivities(config.isim, config.isim_graphql, config.redis, config.neo4j)
        return [*activities.get_activities()]
