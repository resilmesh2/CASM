import asyncio
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from temporalio.client import Client

from config import AppConfig
from temporal.lib.util import start_unique_workflow
from temporal.nmap.topology.activities import NmapTopologyActivities
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
        activities = NmapTopologyActivities(config.nmap_topology, config.neo4j, config.isim)
        return [*activities.get_activities()]


async def main() -> None:
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    await start_unique_workflow(NmapTopologyWorkflow, config.temporal.casm_task_queue, client)


if __name__ == "__main__":
    asyncio.run(main())
