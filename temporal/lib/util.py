import asyncio
import uuid

from structlog import getLogger
from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError


async def run_command_with_output(
    command: list[str], cwd: str | None = None, input_data: str | None = None
) -> tuple[str, str, int]:
    print("Running command: ", *command)

    # Create subprocess with pipes for stdout and stderr
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if input_data else None,
        cwd=cwd,
    )

    # Communicate with the process
    if input_data:
        stdout, stderr = await process.communicate(input=input_data.encode())
    else:
        stdout, stderr = await process.communicate()

    # Decode output
    stdout_str = stdout.decode("utf-8") if stdout else ""
    stderr_str = stderr.decode("utf-8") if stderr else ""

    return stdout_str, stderr_str, process.returncode


def get_unique_subdomains(*data: str) -> str:
    unique_subdomains = set()
    for item in data:
        unique_subdomains.update(item.splitlines())
    return "\n".join(unique_subdomains)


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
