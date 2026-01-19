import logging
import pathlib
from datetime import datetime

import httpx
import yaml

from temporalio import activity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

COMPONENT_CONFIG_PATH = "/config/component_automation_config.yaml"


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

    def ensure_base_risk_automation(self) -> None:
        """
        Create/ensure a default 'base-risk' automation in the main risk config
        so the RiskFormula workflow has something to execute.
        Combines criticality + cvss_score + threatScore into 'Risk Score'.
        """
        try:
            RISK_CONFIG_PATH = "/config/risk_assessment_config.yaml"

            try:
                with pathlib.Path(RISK_CONFIG_PATH).open() as file:
                    cfg = yaml.safe_load(file)
                    if cfg is None:
                        cfg = {}
            except FileNotFoundError:
                cfg = {}

            if "active_automations" not in cfg:
                cfg["active_automations"] = {}

            autos = cfg["active_automations"]
            if "base-risk" not in autos:
                autos["base-risk"] = {
                    "id": "base-risk",
                    "formula_name": "Base Risk",
                    "calculation_method": "weighted_avg",
                    "custom_formula": "",
                    "formula_config": {"criticality": 0.333, "cvss": 0.333, "threat": 0.333},
                    "components": [
                        {
                            "name": "Criticality",
                            "neo4jProperty": "criticality",
                            "weight": 0.333,
                            "max_value": 10,
                            "current_value": 0,
                            "type": "centrality",
                        },
                        {
                            "name": "CVSS",
                            "neo4jProperty": "cvss_score",
                            "weight": 0.333,
                            "max_value": 10,
                            "current_value": 0,
                            "type": "vulnerability",
                        },
                        {
                            "name": "Threat",
                            "neo4jProperty": "threatScore",
                            "weight": 0.333,
                            "max_value": 10,
                            "current_value": 0,
                            "type": "threat",
                        },
                    ],
                    "target_type": "all",
                    "target_values": [],
                    "target_property": "Risk Score",
                    "update_frequency": "hourly",
                    "enabled": True,
                    "created_date": datetime.now().isoformat(),
                    "hasSchedule": False,
                }

                pathlib.Path(pathlib.Path(RISK_CONFIG_PATH).parent).mkdir(exist_ok=True, parents=True)
                with pathlib.Path(RISK_CONFIG_PATH).open("w") as file:
                    yaml.dump(cfg, file, default_flow_style=False)
                logger.info("Created base-risk automation in risk_assessment_config.yaml")

        except Exception as e:
            logger.warning(f"Could not ensure base risk automation: {e}")
