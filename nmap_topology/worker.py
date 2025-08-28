import asyncio

from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions
from nmap_topology.workflow import NmapTopologyWorkflow
from config import AppConfig


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url, namespace=config.temporal.namespace)
    workflows = [NmapTopologyWorkflow]
    activities = []
    for workflow in workflows:
        activities += workflow.get_activities()
    workflow_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "nmap_topology",
            "config"
        )
    )

    worker = Worker(
        client=client,
        task_queue="nmap_topology",
        workflows=workflows,
        activities=activities,
        workflow_runner=workflow_runner,
    )

    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
