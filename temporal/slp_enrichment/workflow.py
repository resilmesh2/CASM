import asyncio
import uuid
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

import structlog
from structlog import getLogger
from temporalio import workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy

from config import AppConfig
from temporal.slp_enrichment.activities import SLPEnrichmentActivities

logger = structlog.get_logger()


@workflow.defn(name="SLPEnrichmentWorkflow")
class SLPEnrichmentWorkflow:
    """
    A workflow that executes enrichment of information about assets using SLP API.
    """

    @workflow.run
    async def run(self) -> None:
        """
        This method runs three activities for accomplishing SLP enrichment.
        :return: None
        """

        config = AppConfig().get()
        slp_enrichment_config = config.slp_enrichment

        asset_info = await workflow.execute_activity(
            SLPEnrichmentActivities.get_asset_info,
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError"],
            ),
            start_to_close_timeout=timedelta(minutes=60),
        )

        domains_ips_for_storing = await workflow.execute_activity(
            SLPEnrichmentActivities.get_data_from_slp,
            args=[asset_info, slp_enrichment_config.x_api_key],
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
            SLPEnrichmentActivities.store_data_from_slp,
            arg=domains_ips_for_storing,
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
        activities = SLPEnrichmentActivities(config.isim)
        return [*activities.get_activities()]


async def main() -> None:
    """
    Entry point for starting the SLP enrichment workflow.
    :return: None
    """

    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    logger = getLogger()
    workflow_id = uuid.uuid4().hex
    # noinspection PyTypeChecker
    workflow_handle = await client.start_workflow(
        SLPEnrichmentWorkflow.run,
        args=(),
        id=workflow_id,
        task_queue=config.temporal.slp_enrichment_task_queue,
        id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE,
    )
    workflow_description = await workflow_handle.describe()
    logger.info("Workflow start requested.", workflow_id=workflow_description.id, run_id=workflow_description.run_id)


if __name__ == "__main__":
    asyncio.run(main())
