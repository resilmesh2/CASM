import asyncio

from easyeasm_demo.config import AppConfig
from easyeasm_demo.workflow import EasyEasmDemoWorkflow
from temporalio.client import Client


async def main() -> None:
    config = AppConfig.get()
    temporal_client = await Client.connect(config.temporal.url, namespace=config.temporal.namespace)
    domains = ["hackerone.com"]
    mode = "fast"
    scan_uuid = "a69c6fabd4eb45f8a2d0554a9046810a"
    await temporal_client.start_workflow(
        EasyEasmDemoWorkflow,
        id=scan_uuid,
        args=(
            scan_uuid,
            domains,
            mode,
        ),
        task_queue=config.temporal.task_queue,
    )


if __name__ == "__main__":
    asyncio.run(main())
