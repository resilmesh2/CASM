import asyncio

from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from config import AppConfig
from temporal.easm.active_enumeration.workflow import ActiveEnumeratonWorkflow
from temporal.easm.parent_workflow import ParentEasmWorkflow
from temporal.easm.passive_enumeration.workflow import PassiveEnumerationWorkflow


async def main() -> None:
    """
    Entry point for creating a worker that runs ParentEasmWorkflow.
    :return: None
    """
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    workflows = [ParentEasmWorkflow, PassiveEnumerationWorkflow, ActiveEnumeratonWorkflow]
    activities = ParentEasmWorkflow.get_activities()
    workflow_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules("temporal.easm", "config")
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
