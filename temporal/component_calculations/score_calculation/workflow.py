import logging
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Any

from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleAlreadyRunningError,
    ScheduleIntervalSpec,
    ScheduleSpec,
    ScheduleState,
)
from temporalio.common import RetryPolicy

from config import AppConfig, ISIMUrlsConfig, TemporalConfig
from temporal.component_calculations.score_calculation.activities import ComponentScoreCalculationActivities
from temporalio import workflow

logger = logging.getLogger(__name__)


@workflow.defn
class ComponentScoreCalculationWorkflow:
    """Workflow for calculating component scores on a schedule"""

    @workflow.run
    async def run(self, component_data: dict[str, Any]) -> dict[str, Any]:
        component_data.get("component_id")
        component_name = component_data.get("component_name")

        workflow.logger.info(f"Starting component calculation workflow for {component_name}")

        result = await workflow.execute_activity(
            ComponentScoreCalculationActivities.calculate_component_score,
            arg=component_data,
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

    @classmethod
    async def initialize_core_component_schedules(
        cls, client: Client, temporal_config: TemporalConfig, isim_urls: ISIMUrlsConfig
    ) -> None:
        """Initialize schedules for core risk components"""
        logger.info("Initializing core component schedules...")

        core_components = [
            {
                "schedule_id": "component-schedule-criticality",
                "component_id": "criticality",
                "component_name": "Criticality Score",
                "neo4j_property": "criticality",
                "execution_endpoint": f"{isim_urls.risk_url}/api/components/execute/criticality",
                "interval": timedelta(hours=1),
                "description": "Calculates criticality based on betweenness and degree centrality",
            },
            {
                "schedule_id": "component-schedule-threatScore",
                "component_id": "threatScore",
                "component_name": "Threat Score",
                "neo4j_property": "threatScore",
                "execution_endpoint": f"{isim_urls.risk_url}/api/components/execute/threatScore",
                "interval": timedelta(hours=1),
                "description": "Retrieves threat scores from Wazuh security platform",
            },
            {
                "schedule_id": "component-schedule-cvss_score",
                "component_id": "cvss_score",
                "component_name": "Vulnerability Score (CVSS)",
                "neo4j_property": "cvss_score",
                "execution_endpoint": f"{isim_urls.risk_url}/api/components/execute/cvss_score",
                "interval": timedelta(hours=1),
                "description": "Calculates CVSS vulnerability scores from CVE data",
            },
        ]

        for component in core_components:
            workflow_input = {
                "component_id": component["component_id"],
                "component_name": component["component_name"],
                "neo4j_property": component["neo4j_property"],
                "execution_endpoint": f"{isim_urls.risk_url}/api/components/execute/{component['component_id']}",
                "update_frequency": "hourly",
            }

            schedule = Schedule(
                action=ScheduleActionStartWorkflow(
                    ComponentScoreCalculationWorkflow.run,
                    arg=workflow_input,
                    id=f"component-calc-{component['component_id']}",
                    task_queue=temporal_config.shared_task_queue,
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
                    f"Could not create schedule '{component['schedule_id']}' at {temporal_config.url} "
                    f"(ns={temporal_config.namespace}): {e}\n{traceback.format_exc()}"
                )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = ComponentScoreCalculationActivities(config.isim_urls)
        return [*activities.get_activities()]
