import asyncio

from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from config import AppConfig
from temporal.nmap.basic.workflow import NmapBasicWorkflow
from temporal.nmap.topology.workflow import NmapTopologyWorkflow


async def main() -> None:
    """
    Entry point for creating a worker that runs nmap basic and topology workflows.
    :return: None
    """
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    workflows = [NmapBasicWorkflow, NmapTopologyWorkflow]
    activities = []
    for workflow in workflows:
        activities += workflow.get_activities()
    workflow_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "temporal.nmap.basic", "temporal.nmap.topology", "config"
        )
    )

    worker = Worker(
        client=client,
        task_queue=config.temporal.nmap_task_queue,
        workflows=workflows,
        activities=activities,
        workflow_runner=workflow_runner,
    )

    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
