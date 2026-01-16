from temporalio import workflow
from temporalio.common import RetryPolicy
from datetime import timedelta
import logging
import os

logger = logging.getLogger(__name__)

RISK_API_URL = os.environ.get("RISK_API_URL", "http://resilmesh-sap-isim-automation:5000")

@workflow.defn
class ComponentCalculationWorkflow:
    """Workflow for calculating component scores on a schedule"""

    @workflow.run
    async def run(self, component_data: dict) -> dict:
        component_id = component_data.get('component_id')
        component_name = component_data.get('component_name')
        
        workflow.logger.info(f"Starting component calculation workflow for {component_name}")
        
        result = await workflow.execute_activity(
            "calculate_component_score",
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