from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from config import AppConfig
from temporalio import workflow


@workflow.defn(name="NucleiWorkflow")
class NucleiWorkflow:
    """
    Workflow that runs a basic nmap scan, parses the XML, and publishes results to ISIM.
    """

    @workflow.run
    async def run(self, input_: dict[str, Any] | None = None) -> None:
        """
        Execute the basic nmap workflow end-to-end.

        :param input_: Optional mapping compatible with NmapBasicConfig to override defaults.
        :return: None
        """
        # config = AppConfig.get()
        # nuclei_config = config.nuclei

        # if input_ is not None:
        #     nuclei_config = await workflow.execute_activity(
        #         NucleiActivities.validate_input,
        #         arg=input_,
        #         retry_policy=RetryPolicy(maximum_attempts=1),
        #         start_to_close_timeout=timedelta(minutes=5),
        #     )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        """
        Collect all activity callables used by the basic nmap workflow.

        :return: A flat sequence of activity functions to be registered with a worker.
        """
        config = AppConfig.get()
        activities = NucleiWorkflow(config.isim)
        return [*activities.get_activities()]
