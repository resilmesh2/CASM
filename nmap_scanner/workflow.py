from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from easyeasm_demo.config import AppConfig
from nmap_scanner.activities import NmapActivities
from nmap_scanner.dtos import NmapResults
from temporalio import workflow


@workflow.defn
class NmapWorkflow:
    @workflow.run
    async def run(self) -> None:
        nmap_results = await workflow.execute_activity(
            NmapActivities.run_nmap_scan,
            start_to_close_timeout=30
        )

        await workflow.execute_activity(
            NmapActivities.parse_nmap_xml,
            nmap_results,
            start_to_close_timeout=30
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = NmapActivities(config.nmap)
        return [*activities.get_activities()]
