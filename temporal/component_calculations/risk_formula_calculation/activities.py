import logging
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import httpx
from temporalio import activity

from config import ISIMUrlsConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComponentRiskFormulaActivities:
    def __init__(self, isim_urls: ISIMUrlsConfig) -> None:
        self.isim_urls = isim_urls

    """Activities for passive component calculations"""

    @activity.defn
    async def execute_risk_formula(self, automation_id: str) -> dict[str, Any]:
        """Execute a risk formula automation via the API"""

        try:
            url = f"{self.isim_urls.risk_url}/api/automations/execute/{automation_id}"
            logger.info(f"Calling risk formula API: {url}")

            async with httpx.AsyncClient() as client:
                resp = await client.post(url, timeout=300.0)
                resp.raise_for_status()
                payload = resp.json()

            logger.info(f"Risk formula '{automation_id}' executed successfully")
            return {"success": True, "automation_id": automation_id, "result": payload}

        except Exception as e:
            logger.exception(f"Risk formula '{automation_id}' failed: {e}")
            return {"success": False, "automation_id": automation_id, "error": str(e)}

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.execute_risk_formula]
