import logging
import os
import pathlib
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

import yaml
from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleAlreadyRunningError,
    ScheduleIntervalSpec,
    ScheduleSpec,
    ScheduleState,
)
from temporalio.common import RetryPolicy

from config import AppConfig
from temporal.component_calculations.risk_formula_calculation.activities import ComponentRiskFormulaActivities
from temporalio import workflow

logger = logging.getLogger(__name__)

RISK_API_URL = os.environ.get("RISK_API_URL", "http://resilmesh_sap_isim_automation:5000")
COMPONENT_CONFIG_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent / "config" / "component_automation_config.yaml"
)


def _load_component_config() -> dict[str, Any]:
    """Load or create component configuration"""
    try:
        with pathlib.Path(COMPONENT_CONFIG_PATH).open() as file:
            config: dict[str, Any] | None = yaml.safe_load(file)
            if config is None:
                config = {}
    except FileNotFoundError:
        config = {}

    if "active_component_automations" not in config:
        config["active_component_automations"] = {}

    return config


def _save_component_config(config: dict[str, Any]) -> bool | None:
    """Save component configuration"""
    try:
        pathlib.Path(pathlib.Path(COMPONENT_CONFIG_PATH).parent).mkdir(exist_ok=True, parents=True)
        with pathlib.Path(COMPONENT_CONFIG_PATH).open("w") as file:
            yaml.dump(config, file, default_flow_style=False)
        return True
    except Exception as e:
        logger.debug(f"Could not save config (non-fatal): {e}")
        return False


@workflow.defn
class RiskFormulaCalculationWorkflow:
    """Runs a saved risk formula automation via the API."""

    @workflow.run
    async def run(self, data: dict[str, str]) -> dict[str, Any]:
        automation_id = data.get("automation_id")
        if not automation_id:
            workflow.logger.error("RiskFormulaCalculationWorkflow missing automation_id")
            return {"success": False, "error": "automation_id required"}

        workflow.logger.info(f"Executing risk formula automation '{automation_id}'")

        result = await workflow.execute_activity(
            ComponentRiskFormulaActivities.execute_risk_formula,
            automation_id,
            start_to_close_timeout=timedelta(seconds=300),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=30),
                backoff_coefficient=2.0,
                maximum_attempts=3,
            ),
        )

        workflow.logger.info(f"Risk formula automation complete: {result}")
        return result

    @classmethod
    async def initialize_base_risk_schedule(cls, client: Client) -> None:
        """
        Create a Temporal schedule for the 'base-risk' formula that runs
        30 minutes after the component schedules (which are every 2 hours).
        """

        schedule_id = "automation-schedule-base-risk"
        workflow_input = {"automation_id": "base-risk"}
        spec = ScheduleSpec(intervals=[ScheduleIntervalSpec(every=timedelta(hours=1), offset=timedelta(minutes=30))])

        schedule = Schedule(
            action=ScheduleActionStartWorkflow(
                RiskFormulaCalculationWorkflow.run,
                arg=workflow_input,
                id="risk-formula-calc-base-risk",
                task_queue="component-calculations",
            ),
            spec=spec,
            state=ScheduleState(note="Base Risk (Criticality + CVSS + Threat) every 2h, offset 30m", paused=False),
        )

        try:
            await client.create_schedule(schedule_id, schedule)
            logger.info(f"Created schedule '{schedule_id}' (every 2h, +30m offset)")
            cfg = _load_component_config()
            if "active_automations" in cfg and "base-risk" in cfg["active_automations"]:
                cfg["active_automations"]["base-risk"]["hasSchedule"] = True
                _save_component_config(cfg)

        except ScheduleAlreadyRunningError:
            logger.info(f"Schedule '{schedule_id}' already exists, skipping creation")

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = ComponentRiskFormulaActivities(config.isim_urls)
        return [*activities.get_activities()]
