import logging
import os
from datetime import timedelta

from temporalio.common import RetryPolicy

from temporalio import workflow

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


async def initialize_core_component_schedules(self, client: Client) -> None:
    """Initialize schedules for core risk components"""
    logger.info("Initializing core component schedules...")

    core_components = [
        {
            "schedule_id": "component-schedule-criticality",
            "component_id": "criticality",
            "component_name": "Criticality Score",
            "neo4j_property": "criticality",
            "execution_endpoint": f"{RISK_API_URL}/api/components/execute/criticality",
            "interval": timedelta(hours=1),
            "description": "Calculates criticality based on betweenness and degree centrality",
        },
        {
            "schedule_id": "component-schedule-threatScore",
            "component_id": "threatScore",
            "component_name": "Threat Score",
            "neo4j_property": "threatScore",
            "execution_endpoint": f"{RISK_API_URL}/api/components/execute/threatScore",
            "interval": timedelta(hours=1),
            "description": "Retrieves threat scores from Wazuh security platform",
        },
        {
            "schedule_id": "component-schedule-cvss_score",
            "component_id": "cvss_score",
            "component_name": "Vulnerability Score (CVSS)",
            "neo4j_property": "cvss_score",
            "execution_endpoint": f"{RISK_API_URL}/api/components/execute/cvss_score",
            "interval": timedelta(hours=1),
            "description": "Calculates CVSS vulnerability scores from CVE data",
        },
    ]

    for component in core_components:
        workflow_input = {
            "component_id": component["component_id"],
            "component_name": component["component_name"],
            "neo4j_property": component["neo4j_property"],
            "execution_endpoint": f"{RISK_API_URL}/api/components/execute/{component['component_id']}",
            "update_frequency": "hourly",
        }

        schedule = Schedule(
            action=ScheduleActionStartWorkflow(
                "ComponentCalculationWorkflow",
                args=[workflow_input],
                id=f"component-calc-{component['component_id']}",
                task_queue="component-calculations",
            ),
            spec=ScheduleSpec(intervals=[ScheduleIntervalSpec(every=component["interval"])]),
            state=ScheduleState(note=component["description"], paused=False),
        )

        try:
            await client.create_schedule(component["schedule_id"], schedule)
            logger.info(f"Created schedule '{component['schedule_id']}' (runs every 2 hours)")
        except ScheduleAlreadyRunningError:
            logger.info(f"Schedule '{component['schedule_id']}' already exists, skipping creation")
        except Exception as e:
            import traceback

            logger.warning(
                f"Could not create schedule '{component['schedule_id']}' at {TEMPORAL_ADDRESS} "
                f"(ns={TEMPORAL_NAMESPACE}): {e}\n{traceback.format_exc()}"
            )
