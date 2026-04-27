import asyncio

from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from config import AppConfig
from easyeasm_demo.workflow import EasyEasmWorkflow
from temporal.lib import redis_handler
from temporal.lib.observability import configure_logging


async def main() -> None:
    config = AppConfig.get()
    configure_logging("easyeasm-demo-worker", config.logging)
    client = await Client.connect(config.temporal.url, namespace=config.temporal.namespace)
    workflows = [EasyEasmWorkflow]
    activities = []
    for workflow in workflows:
        activities += workflow.get_activities()
    workflow_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules("easyeasm_demo", "config")
    )
    redis_handler.init_redis()

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
