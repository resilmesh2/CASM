import asyncio
import logging
import os
import pathlib
from datetime import datetime, timedelta

import httpx
import yaml
from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleAlreadyRunningError,
    ScheduleIntervalSpec,
    ScheduleSpec,
    ScheduleState,
)
from temporalio.worker import Worker

from component_calculation import ComponentCalculationWorkflow, RiskFormulaCalculationWorkflow
from temporalio import activity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TEMPORAL_HOST = os.environ.get("TEMPORAL_HOST", "resilmesh_sop_wo_temporal")
TEMPORAL_PORT = os.environ.get("TEMPORAL_PORT", "7233")
TEMPORAL_NAMESPACE = os.environ.get("TEMPORAL_NAMESPACE", "default")
TEMPORAL_ADDRESS = f"{TEMPORAL_HOST}:{TEMPORAL_PORT}"
RISK_API_URL = os.environ.get("RISK_API_URL", "http://resilmesh_sap_isim_automation:5000")
COMPONENT_CONFIG_PATH = "/config/component_automation_config.yaml"


def load_component_config():
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


def save_component_config(config) -> bool | None:
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
async def calculate_component_score(component_data: dict) -> dict:
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
                "timestamp": datetime.now().isoformat(),
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


@activity.defn
async def execute_risk_formula(automation_id: str) -> dict:
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


def ensure_base_risk_automation() -> None:
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


async def initialize_core_component_schedules(client: Client) -> None:
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


async def initialize_base_risk_schedule(client: Client) -> None:
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


async def main() -> None:
    """Start the Temporal worker with core component schedules"""
    logger.info(f"Connecting to Temporal at {TEMPORAL_ADDRESS} (ns={TEMPORAL_NAMESPACE})")
    logger.info(f"Risk API URL: {RISK_API_URL}")

    max_retries = 20
    retry_interval = 10

    for attempt in range(1, max_retries + 1):
        try:
            client = await Client.connect(TEMPORAL_ADDRESS, namespace=TEMPORAL_NAMESPACE)
            logger.info(f"Successfully connected to Temporal on attempt {attempt}")
            break
        except Exception as e:
            logger.warning(f"Connection attempt {attempt}/{max_retries} failed: {e}")
            if attempt == max_retries:
                logger.exception("Max retries reached. Could not connect to Temporal server.")
                raise
            await asyncio.sleep(retry_interval)

    await initialize_core_component_schedules(client)
    await initialize_base_risk_schedule(client)

    worker = Worker(
        client,
        task_queue="component-calculations",
        workflows=[ComponentCalculationWorkflow, RiskFormulaCalculationWorkflow],
        activities=[calculate_component_score, execute_risk_formula],
    )

    logger.info("Component scheduler worker started")
    logger.info("Task queue: component-calculations")
    logger.info("Listening for component calculation tasks...")

    await worker.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    except Exception as e:
        logger.exception(f"Worker crashed: {e!s}")
        exit(1)
