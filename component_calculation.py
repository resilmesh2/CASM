from temporalio import workflow
from temporalio.common import RetryPolicy
from datetime import timedelta
import httpx
import logging

logger = logging.getLogger(__name__)

@workflow.defn
class ComponentCalculationWorkflow:
    """Workflow for calculating component scores on a schedule"""

    @workflow.run
    async def run(self) -> dict:
        # Derive component key from the workflow ID (e.g., "criticality-scheduled" -> "criticality")
        wf_id = workflow.info().workflow_id
        component_key = wf_id[:-len("-scheduled")] if wf_id.endswith("-scheduled") else wf_id

        component_map = {
            "criticality": {
                "component_id": "criticality",
                "component_name": "Criticality Score",
                "neo4j_property": "criticality",
                "execution_endpoint": f"{RISK_API_URL}/api/components/execute/criticality",
            },
            "threatScore": {
                "component_id": "threatScore",
                "component_name": "Threat Score",
                "neo4j_property": "threatScore",
                "execution_endpoint": f"{RISK_API_URL}/api/components/execute/threatScore",
            },
            "cvss_score": {
                "component_id": "cvss_score",
                "component_name": "Vulnerability Score (CVSS)",
                "neo4j_property": "cvss_score",
                "execution_endpoint": f"{RISK_API_URL}/api/components/execute/cvss_score",
            },
        }

        component_data = component_map.get(component_key)
        if not component_data:
            workflow.logger.error(f"Unknown component key from workflow_id '{wf_id}'")
            return {"success": False, "error": f"Unknown component key '{component_key}'"}

        workflow.logger.info(f"Starting component calculation workflow for {component_data['component_name']}")

        result = await workflow.execute_activity(
            calculate_component_score,
            component_data,
            start_to_close_timeout=timedelta(seconds=300),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=30),
                backoff_coefficient=2.0,
                maximum_attempts=3,
            ),
        )

        workflow.logger.info(f"Component calculation workflow complete: {result}")
        return result
