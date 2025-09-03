import asyncio
import uuid

from temporalio.client import Client

from config import AppConfig
from temporal.nmap.topology.workflow import NmapTopologyWorkflow


async def main() -> None:
    config = AppConfig.get()
    temporal_client = await Client.connect(config.temporal.url, namespace=config.temporal.namespace)
    scan_uuid = uuid.uuid4().hex
    await temporal_client.start_workflow(
        NmapTopologyWorkflow,
        id=scan_uuid,
        task_queue="nmap_topology",
    )


if __name__ == "__main__":
    asyncio.run(main())
