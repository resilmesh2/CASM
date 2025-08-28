from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from config import AppConfig
from nmap_topology.activities import NmapTopologyActivities
from temporalio import workflow


@workflow.defn(name="NmapTopologyWorkflow")
class NmapTopologyWorkflow:
    @workflow.run
    async def run(self) -> None:
        nmap_results = await workflow.execute_activity(
            NmapTopologyActivities.run_nmap_traceroute_scan,
            start_to_close_timeout=timedelta(minutes=60),
        )

        await workflow.execute_activity(
            NmapTopologyActivities.nmap_traceroute_neo4j,
            nmap_results,
            start_to_close_timeout=timedelta(minutes=60),
        )

        await workflow.execute_activity(
            NmapTopologyActivities.compute_criticalities,
            start_to_close_timeout=timedelta(minutes=60),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = NmapTopologyActivities(config.topology, config.neo4j, config.isim)
        return [*activities.get_activities()]
