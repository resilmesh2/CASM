import asyncio
import logging
import os
import requests
from datetime import datetime, timedelta
from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.worker import Worker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TEMPORAL_URL = os.environ.get("TEMPORAL_URL", "temporal:7233")
RISK_API_URL = os.environ.get("RISK_API_URL", "http://risk-api:5000")

@activity.defn
async def calculate_component_score(component_data: dict) -> dict:
    """Calculate score for a single component by calling the risk API"""
    try:
        component_id = component_data.get('component_id')
        component_name = component_data.get('component_name')
        neo4j_property = component_data.get('neo4j_property')
        
        logger.info(f"Calculating score for component: {component_name} ({component_id})")
        
        # Call the risk API to execute the component calculation
        execution_endpoint = component_data.get('execution_endpoint')
        
        if execution_endpoint:
            # Use the provided execution endpoint
            api_url = execution_endpoint
            logger.info(f"Using custom endpoint: {api_url}")
        else:
            # Use default component execution endpoint
            api_url = f"{RISK_API_URL}/api/risk/components/execute/{neo4j_property or component_id}"
            logger.info(f"Using default endpoint: {api_url}")
        
        try:
            response = requests.post(api_url, json={}, timeout=60)
            response.raise_for_status()
            
            api_result = response.json()
            
            result = {
                'success': True,
                'component_id': component_id,
                'component_name': component_name,
                'nodes_updated': api_result.get('nodes_updated', 0),
                'avg_value': api_result.get('avg_value', 0),
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"Component {component_name} calculation complete: {result['nodes_updated']} nodes updated")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed for {component_name}: {str(e)}")
            return {
                'success': False,
                'component_id': component_id,
                'component_name': component_name,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
        
    except Exception as e:
        logger.error(f"Error calculating component score: {str(e)}")
        return {
            'success': False,
            'component_id': component_data.get('component_id'),
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

@workflow.defn
class ComponentCalculationWorkflow:
    """Workflow for calculating component scores on a schedule"""
    
    @workflow.run
    async def run(self, component_data: dict) -> dict:
        workflow.logger.info(f"Starting component calculation workflow for {component_data.get('component_name')}")
        
        # Execute the calculation activity with retry policy
        result = await workflow.execute_activity(
            calculate_component_score,
            component_data,
            start_to_close_timeout=timedelta(seconds=300),
            retry_policy=workflow.RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=30),
                backoff_coefficient=2.0,
                maximum_attempts=3
            )
        )
        
        workflow.logger.info(f"Component calculation workflow complete: {result}")
        return result

async def main():
    """Start the Temporal worker"""
    logger.info(f"Connecting to Temporal at {TEMPORAL_URL}")
    logger.info(f"Risk API URL: {RISK_API_URL}")
    
    try:
        client = await Client.connect(TEMPORAL_URL)
        logger.info("Successfully connected to Temporal")
        
        worker = Worker(
            client,
            task_queue="component-calculations",
            workflows=[ComponentCalculationWorkflow],
            activities=[calculate_component_score]
        )
        
        logger.info("Component scheduler worker started")
        logger.info("Task queue: component-calculations")
        logger.info("Listening for component calculation tasks...")
        
        await worker.run()
        
    except Exception as e:
        logger.error(f"Failed to start worker: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    except Exception as e:
        logger.error(f"Worker crashed: {str(e)}")
        exit(1)