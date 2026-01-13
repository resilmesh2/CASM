import asyncio
import uuid
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from logging import getLogger
from typing import Any

from temporalio import workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy

from config import AppConfig, EasmScannerConfig
from temporal.easm.active_enumeration.activities import ActiveEnumerationActivities
from temporal.easm.active_enumeration.workflow import ActiveEnumeratonWorkflow
from temporal.easm.activities import EasmActivities
from temporal.easm.passive_enumeration.activities import PassiveEnumerationActivities
from temporal.easm.passive_enumeration.workflow import PassiveEnumerationWorkflow


@workflow.defn
class ParentEasmWorkflow:
    """
    Orchestrates the full EASM workflow: passive enumeration, optional active enumeration,
    service probing via httpx, and publishing results to ISIM.
    """

    @workflow.run
    async def run(self, input_: dict[str, Any] | None = None) -> str:
        """
        Run the parent EASM workflow.

        If an input mapping is provided, it is validated and used to override the
        default configuration. The workflow then runs passive enumeration to
        gather subdomains, optionally performs active enumeration (bruteforce and
        permutations), probes discovered domains with httpx, and finally posts
        parsed results to the ISIM API.

        :param input_: Optional mapping compatible with EasmScannerConfig to override defaults.
        :return: The response body returned by the ISIM API after posting results.
        """
        config = AppConfig.get()
        easm_config: EasmScannerConfig = config.easm_scanner

        if input_ is not None:
            easm_config = await workflow.execute_activity(
                EasmActivities.validate_input,
                arg=input_,
                retry_policy=RetryPolicy(
                    maximum_attempts=1,
                ),
                start_to_close_timeout=timedelta(minutes=5),
            )

        domains_output_uuid = await workflow.execute_child_workflow(
            PassiveEnumerationWorkflow.run,
            args=[easm_config.domains],
            id=f"passive-{workflow.info().workflow_id}",
            task_queue=config.temporal.easm_task_queue,
        )

        if easm_config.complete:
            domains_output_uuid: str = await workflow.execute_child_workflow(
                ActiveEnumeratonWorkflow.run,
                args=[domains_output_uuid, easm_config.wordlist_path, str(easm_config.threads)],
                id=f"active-{workflow.info().workflow_id}",
                task_queue=config.temporal.easm_task_queue,
            )

        httpx_uuid = await workflow.execute_activity(
            EasmActivities.run_httpx,
            args=[domains_output_uuid, easm_config.httpx_path],
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=2,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError", "EnumerationToolError"],
            ),
            start_to_close_timeout=timedelta(minutes=60),
        )

        return await workflow.execute_activity(
            EasmActivities.parse_result_and_send_to_api,
            args=[httpx_uuid],
            start_to_close_timeout=timedelta(minutes=5),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        """
        Collect all activity callables used by the EASM workflows.

        :return: A flat sequence of activity functions to be registered with a worker.
        """
        config = AppConfig.get()
        passive_enum_activities = PassiveEnumerationActivities(config.redis)
        active_enum_activities = ActiveEnumerationActivities(config.redis)
        activities = EasmActivities(config.redis, config.isim)
        return [
            *passive_enum_activities.get_activities(),
            *active_enum_activities.get_activities(),
            *activities.get_activities(),
        ]


async def main() -> None:
    """
    Convenience entry point to start the ParentEasmWorkflow from the CLI.

    Connects to the Temporal server, starts a workflow run on the configured task
    queue, and logs basic information about the request.

    :return: None
    """
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    logger = getLogger()
    workflow_id = uuid.uuid4().hex
    # noinspection PyTypeChecker
    workflow_handle = await client.start_workflow(
        ParentEasmWorkflow.run,
        args=(),
        id=workflow_id,
        task_queue=config.temporal.easm_task_queue,
        id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE,
    )
    workflow_description = await workflow_handle.describe()
    logger.info("Workflow start requested.", workflow_id=workflow_description.id, run_id=workflow_description.run_id)


if __name__ == "__main__":
    asyncio.run(main())
