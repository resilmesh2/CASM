import asyncio
from typing import TYPE_CHECKING, Any

from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from config import AppConfig
from temporal.component_calculations.risk_formula_calculation.workflow import RiskFormulaCalculationWorkflow
from temporal.component_calculations.score_calculation.workflow import ComponentScoreCalculationWorkflow
from temporal.lib import redis_handler
from temporal.nmap.basic.workflow import NmapBasicWorkflow
from temporal.nmap.topology.workflow import NmapTopologyWorkflow
from temporal.nuclei.workflow import NucleiWorkflow

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


async def main() -> None:
    """
    Entry point for creating a worker that runs nmap (basic, topology) and nuclei workflows.
    :return: None
    """
    config = AppConfig.get()
    client = await Client.connect(config.temporal.url)
    workflows = [NmapBasicWorkflow, NmapTopologyWorkflow, NucleiWorkflow, ComponentScoreCalculationWorkflow, RiskFormulaCalculationWorkflow]
    activities: list[Callable[..., Awaitable[Any]]] = []
    for workflow in workflows:
        activities += workflow.get_activities()
    workflow_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "temporal.nmap.basic", "temporal.nmap.topology", "temporal.nuclei", "config", "temporal.component_calculations"
        )
    )
    redis_handler.init_redis()

    await ComponentScoreCalculationWorkflow.initialize_core_component_schedules(client, config.temporal, config.isim_urls)
    await RiskFormulaCalculationWorkflow.initialize_base_risk_schedule(client)

    worker = Worker(
        client=client,
        task_queue=config.temporal.scanning_task_queue,
        workflows=workflows,
        activities=activities,
        workflow_runner=workflow_runner,
    )

    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
