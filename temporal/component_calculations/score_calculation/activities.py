import logging
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any

from pytz import UTC

from temporalio import activity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComponentScoreCalculationActivities:
    """Activities for passive component calculations"""

    @activity.defn
    async def calculate_component_score(self, component_data: dict[str, Any]) -> dict[str, Any]:
        """Calculate score for a single component by calling the risk API"""
        import requests

        try:
            component_id = component_data.get("component_id")
            component_name = component_data.get("component_name")
            neo4j_property = component_data.get("neo4j_property")

            logger.info(f"Calculating score for component: {component_name} ({component_id})")

            execution_endpoint = component_data.get("execution_endpoint")

            if execution_endpoint:
                api_url = execution_endpoint
                logger.info(f"Using custom endpoint: {api_url}")
            else:
                api_url = f"{RISK_API_URL}/api/risk/components/execute/{neo4j_property or component_id}"
                logger.info(f"Using default endpoint: {api_url}")

            try:
                response = requests.post(api_url, json={}, timeout=60)
                response.raise_for_status()

                api_result = response.json()

                result = {
                    "success": True,
                    "component_id": component_id,
                    "component_name": component_name,
                    "nodes_updated": api_result.get("nodes_updated", 0),
                    "avg_value": api_result.get("avg_value", 0),
                    "timestamp": datetime.now(tz=UTC).isoformat(),
                }

                logger.info(f"Component {component_name} calculation complete: {result['nodes_updated']} nodes updated")
                return result

            except requests.exceptions.RequestException as e:
                logger.exception(f"API request failed for {component_name}: {e!s}")
                return {
                    "success": False,
                    "component_id": component_id,
                    "component_name": component_name,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat(),
                }

        except Exception as e:
            logger.exception(f"Error calculating component score: {e!s}")
            return {
                "success": False,
                "component_id": component_data.get("component_id"),
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.calculate_component_score]
