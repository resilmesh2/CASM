import asyncio
from datetime import timedelta

import structlog
from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleAlreadyRunningError,
    ScheduleIntervalSpec,
    ScheduleSpec,
)
from temporalio.exceptions import TemporalError
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from config import AppConfig
from temporal.lib.observability import configure_logging
from temporal.slp_enrichment.workflow import SLPEnrichmentWorkflow


async def main() -> None:
    """
    Entry point for starting the worker and scheduling the enrichment workflows.
    :return: None
    """

    config = AppConfig.get()
    configure_logging("slp-enrichment-worker", config.logging)
    client = await Client.connect(config.temporal.url)
    logger = structlog.get_logger(__name__)
    workflows = [SLPEnrichmentWorkflow]
    activities = SLPEnrichmentWorkflow.get_activities()
    workflow_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules("temporal.slp_enrichment", "config")
    )

    worker = Worker(
        client=client,
        task_queue=config.temporal.slp_enrichment_task_queue,
        workflows=workflows,
        activities=activities,
        workflow_runner=workflow_runner,
    )

    workflow_id = "slp-enrichment-workflow-id"
    schedule_id = "slp-enrichment-schedule-id"
    try:
        async for schedule_item in await client.list_schedules():
            if schedule_item.id == schedule_id:
                raise ScheduleAlreadyRunningError()
        await asyncio.gather(
            worker.run(),
            client.create_schedule(
                schedule_id,
                Schedule(
                    action=ScheduleActionStartWorkflow(
                        SLPEnrichmentWorkflow.run,
                        id=workflow_id,
                        task_queue="slp_enrichment",
                    ),
                    spec=ScheduleSpec(intervals=[ScheduleIntervalSpec(every=timedelta(minutes=60))]),
                ),
            ),
        )
        logger.info("schedule_and_workflow_created", schedule_id=schedule_id, workflow_id=workflow_id)
    except ScheduleAlreadyRunningError:
        try:
            logger.info("schedule_already_running", schedule_id=schedule_id)
            await worker.run()
        except TemporalError:
            logger.info("schedule_and_workflow_already_running", schedule_id=schedule_id)


if __name__ == "__main__":
    asyncio.run(main())
