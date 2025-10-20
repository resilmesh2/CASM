import asyncio

from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from config import AppConfig
from easyeasm_demo.workflow import EasyEasmWorkflow


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url, namespace=config.temporal.namespace)
    workflows = [EasyEasmWorkflow]
    activities = []
    for workflow in workflows:
        activities += workflow.get_activities()
    workflow_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules("easyeasm_demo", "config")
    )

    worker = Worker(
        client=client,
        task_queue=config.temporal.easm_task_queue,
        workflows=workflows,
        activities=activities,
        workflow_runner=workflow_runner,
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
