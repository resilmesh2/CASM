from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from easyeasm_demo.config import AppConfig
from temporal.nmap_scanner.activities import NmapActivities
from temporalio import workflow


@workflow.defn(name="NmapWorkflow")
class NmapWorkflow:
    @workflow.run
    async def run(self) -> None:
        nmap_results = await workflow.execute_activity(
            NmapActivities.run_nmap_scan,
            start_to_close_timeout=timedelta(minutes=5),
        )

        parsed_nmap_results = await workflow.execute_activity(
            NmapActivities.parse_nmap_xml,
            nmap_results,
            start_to_close_timeout=timedelta(minutes=5),
        )

        await workflow.execute_activity(
            NmapActivities.send_result_to_api,
            parsed_nmap_results,
            start_to_close_timeout=timedelta(minutes=5),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = NmapActivities(config.nmap, config.isim)
        return [*activities.get_activities()]
