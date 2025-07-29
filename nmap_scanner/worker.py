import asyncio

from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from easyeasm_demo.config import AppConfig, TemporalConfig
from easyeasm_demo.workflow import EasyEasmWorkflow, logger
from nmap_scanner.workflow import NmapWorkflow
from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions


async def start_unique_workflow(workflow, workflow_id: str, client: Client) -> None:

    try:
        # noinspection PyTypeChecker
        workflow_handle = await client.start_workflow(
            workflow.run,
            args=(),
            id=workflow_id,
            task_queue="nmap_scanner_task_queue",
            id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE,
        )
        workflow_description = await workflow_handle.describe()
        logger.info(
            "Workflow start requested.", workflow_id=workflow_description.id, run_id=workflow_description.run_id
        )
    except WorkflowAlreadyStartedError as ex:
        workflow_id_ex: str = str(ex.workflow_id)  # pyright: ignore
        logger.warning(
            "Workflow start already requested, doing nothing. "
            "This is normal for multiple workers running concurrently.",
            workflow_id=workflow_id_ex,
        )


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect("localhost:7233")
    workflows = [NmapWorkflow]
    activities = []
    for workflow in workflows:
        activities += workflow.get_activities()
    workflow_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "nmap_scanner",
        )
    )

    worker = Worker(
        client=client,
        task_queue="nmap_scanner_task_queue",
        workflows=workflows,
        activities=activities,
        workflow_runner=workflow_runner,
    )

    await start_unique_workflow(NmapWorkflow, "1", client)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
