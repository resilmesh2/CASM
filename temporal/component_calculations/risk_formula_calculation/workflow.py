import logging
import os
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

logger = logging.getLogger(__name__)

RISK_API_URL = os.environ.get("RISK_API_URL", "http://resilmesh_sap_isim_automation:5000")


@workflow.defn
class RiskFormulaCalculationWorkflow:
    """Runs a saved risk formula automation via the API."""

    @workflow.run
    async def run(self, data: dict) -> dict:
        automation_id = data.get("automation_id")
        if not automation_id:
            workflow.logger.error("RiskFormulaCalculationWorkflow missing automation_id")
            return {"success": False, "error": "automation_id required"}

        workflow.logger.info(f"Executing risk formula automation '{automation_id}'")

        result = await workflow.execute_activity(
            "execute_risk_formula",
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



async def initialize_base_risk_schedule(self, client: Client) -> None:
    """
    Create a Temporal schedule for the 'base-risk' formula that runs
    30 minutes after the component schedules (which are every 2 hours).
    """
    ensure_base_risk_automation()

    schedule_id = "automation-schedule-base-risk"
    workflow_input = {"automation_id": "base-risk"}
    spec = ScheduleSpec(intervals=[ScheduleIntervalSpec(every=timedelta(hours=1), offset=timedelta(minutes=30))])

    schedule = Schedule(
        action=ScheduleActionStartWorkflow(
            "RiskFormulaCalculationWorkflow",
            workflow_input,
            id="risk-formula-calc-base-risk",
            task_queue="component-calculations",
        ),
        spec=spec,
        state=ScheduleState(note="Base Risk (Criticality + CVSS + Threat) every 2h, offset 30m", paused=False),
    )

    try:
        await client.create_schedule(schedule_id, schedule)
        logger.info(f"Created schedule '{schedule_id}' (every 2h, +30m offset)")
        cfg = load_component_config()
        if "active_automations" in cfg and "base-risk" in cfg["active_automations"]:
            cfg["active_automations"]["base-risk"]["hasSchedule"] = True
            save_component_config(cfg)

    except ScheduleAlreadyRunningError:
        logger.info(f"Schedule '{schedule_id}' already exists, skipping creation")
