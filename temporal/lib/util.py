import uuid

from structlog import getLogger
from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError


async def start_unique_workflow(workflow, task_queue: str, client: Client) -> None:
    logger = getLogger()
    workflow_id = uuid.uuid4().hex
    try:
        # noinspection PyTypeChecker
        workflow_handle = await client.start_workflow(
            workflow.run,
            args=(),
            id=workflow_id,
            task_queue=task_queue,
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