from temporalio import workflow
from temporalio.common import RetryPolicy
from datetime import timedelta
import httpx
import logging

logger = logging.getLogger(__name__)

@workflow.defn
class ComponentCalculationWorkflow:
    @workflow.run
    async def run(self, input_data: dict) -> dict:
        component_id = input_data['component_id']
        execution_endpoint = input_data['execution_endpoint']
        
        logger.info(f"Starting component calculation workflow for {component_id}")
        
        try:
            # Call the execution endpoint
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    execution_endpoint,
                    timeout=300.0  # 5 minute timeout
                )
                response.raise_for_status()
                result = response.json()
            
            logger.info(f"Component {component_id} calculation completed: {result}")
            
            return {
                'success': True,
                'component_id': component_id,
                'result': result
            }
            
        except Exception as e:
            logger.error(f"Component calculation failed for {component_id}: {str(e)}")
            return {
                'success': False,
                'component_id': component_id,
                'error': str(e)
            }