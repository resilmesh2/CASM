import asyncio
import uuid

from temporalio.client import Client

from config import AppConfig
from easyeasm_demo.workflow import CASMInput, EasyEasmWorkflow


async def main() -> None:
    config = AppConfig.get()
    temporal_client = await Client.connect(config.temporal.url, namespace=config.temporal.namespace)
    domains = ["vulnweb.com"]
    mode = "fast"
    scan_uuid = uuid.uuid4().hex
    input_ = CASMInput(domains=domains, scan_uuid=scan_uuid, mode=mode)
    await temporal_client.start_workflow(
        EasyEasmWorkflow,
        id=scan_uuid,
        arg=input_.to_dict(),
        task_queue=config.temporal.easm_task_queue,
    )


if __name__ == "__main__":
    asyncio.run(main())
