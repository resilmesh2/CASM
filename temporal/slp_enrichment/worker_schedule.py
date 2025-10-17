import asyncio
from datetime import timedelta

from temporalio.client import Client, Schedule, ScheduleActionStartWorkflow, ScheduleIntervalSpec, ScheduleSpec
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from config import AppConfig
from temporal.slp_enrichment.workflow import SLPEnrichmentWorkflow


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
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

    await asyncio.gather(
        worker.run(),
        client.create_schedule(
            "slp-enrichment-schedule-id",
            Schedule(
                action=ScheduleActionStartWorkflow(
                    SLPEnrichmentWorkflow.run,
                    id="slp-enrichment-workflow-id",
                    task_queue="slp_enrichment",
                ),
                spec=ScheduleSpec(intervals=[ScheduleIntervalSpec(every=timedelta(minutes=60))]),
            ),
        ),
    )


if __name__ == "__main__":
    asyncio.run(main())
