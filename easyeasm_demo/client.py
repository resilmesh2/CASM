from temporalio.client import Client
import asyncio
from uuid import uuid4
from easyeasm_demo.config import AppConfig
from easyeasm_demo.workflow import EasyEasmDemoWorkflow


async def main():
    config = AppConfig.get()
    temporal_client = await Client.connect(config.temporal.url, namespace=config.temporal.namespace)
    domains = ["127.0.0.1"]
    mode="fast"
    await temporal_client.start_workflow(
        EasyEasmDemoWorkflow,
        id=uuid4().hex,
        args=(domains, mode,),
        task_queue=config.temporal.task_queue,
    )


if __name__ == '__main__':
    asyncio.run(main())