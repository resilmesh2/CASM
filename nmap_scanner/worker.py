import asyncio

from easyeasm_demo.config import AppConfig
from easyeasm_demo.workflow import EasyEasmWorkflow
from nmap_scanner.workflow import NmapWorkflow
from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect("localhost:7233")
    workflows = [NmapWorkflow]
    activities = []
    for workflow in workflows:
        activities += workflow.get_activities()
    workflow_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "nmap_scan",
        )
    )

    worker = Worker(
        client=client,
        task_queue=config.temporal.task_queue,
        workflows=workflows,
        activities=activities,
        workflow_runner=workflow_runner,
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
