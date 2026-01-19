import logging
import pathlib
from datetime import datetime

import httpx
import yaml

from temporalio import activity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComponentRiskFormulaActivities:
    """Activities for passive component calculations"""

    def load_component_config(self):
        """Load or create component configuration"""
        try:
            with pathlib.Path(COMPONENT_CONFIG_PATH).open() as file:
                config = yaml.safe_load(file)
                if config is None:
                    config = {}
        except FileNotFoundError:
            config = {}

        if "active_component_automations" not in config:
            config["active_component_automations"] = {}

        return config

    def save_component_config(self, config) -> bool | None:
        """Save component configuration"""
        try:
            pathlib.Path(pathlib.Path(COMPONENT_CONFIG_PATH).parent).mkdir(exist_ok=True, parents=True)
            with pathlib.Path(COMPONENT_CONFIG_PATH).open("w") as file:
                yaml.dump(config, file, default_flow_style=False)
            return True
        except Exception as e:
            logger.debug(f"Could not save config (non-fatal): {e}")
            return False

    @activity.defn
    async def execute_risk_formula(self, automation_id: str) -> dict:
        """Execute a risk formula automation via the API"""

        try:
            url = f"{RISK_API_URL}/api/automations/execute/{automation_id}"
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
