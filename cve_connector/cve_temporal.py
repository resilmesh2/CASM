"""
Module for Scheduling CVE Updates with Temporal

This module implements a Temporal workflow to periodically fetch CVE data for software versions
stored in a Neo4j database, parse the data, and update the database. It uses the NVD API to retrieve
CVE information and integrates with Neo4j via a connector client. The workflow runs on a schedule,
with activities to handle database updates.

Functions:
  - cve_version: Fetches and processes CVEs for software versions.
  - main: Sets up the Temporal client, schedule, and worker.

Classes:
  - CveDatabaseUpdater: Handles database update operations.
  - CveUpdateActivities: Defines Temporal activities for database updates.
  - CveUpdateWorkflow: Defines the Temporal workflow to execute activities.
"""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
import os
import signal
import time
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleAlreadyRunningError,
    ScheduleIntervalSpec,
    ScheduleSpec,
)
from temporalio.common import RetryPolicy
from temporalio.exceptions import TemporalError
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from config import AppConfig, Config
from cve_connector.nvd_cve.cpe_identifier import CpeIdentifier
from cve_connector.nvd_cve.cve_client import search_cve_by_version
from cve_connector.nvd_cve.cve_parser import parse_vulnerabilities
from cve_connector.nvd_cve.CveConnectorClient import CVEConnectorClient
from cve_connector.nvd_cve.toneo4j import (
    move_cve_data_to_neo4j,
)
from temporal.lib import redis_handler
from temporalio import activity, workflow

if TYPE_CHECKING:
    from cve_connector.nvd_cve.nvd_types import NvdCvesApiResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.handlers.TimedRotatingFileHandler(
            filename=f"runtime_{datetime.now().strftime('%Y-%m-%d')}.log",
            when="midnight",
            interval=1,
            backupCount=30,
            encoding="utf-8",
            delay=False,
        ),
        logging.StreamHandler(),
    ],
)


def cve_version(
    workflow_start: datetime, neo4j_password: str, neo4j_bolt: str, neo4j_user: str, nvd_api_key: str
) -> str:
    """
    Fetches and processes CVEs for software versions stored in Neo4j.

    Retrieves software versions from Neo4j, queries the NVD API for CVEs associated with each version
    and CPE part ('a', 'o', 'h'), parses the results, and updates the Neo4j database. Retries API
    calls up to a maximum limit if they fail.

    :param workflow_start: Timestamp when the workflow started.
    :param neo4j_password: Password for Neo4j authentication.
    :param neo4j_bolt: Bolt connection string for Neo4j.
    :param neo4j_user: Username for Neo4j authentication.
    :param nvd_api_key: API key for NVD API authentication.
    :return: None
    :raises Exception: If Neo4j operations fail due to connection or query issues.
    """
    cve_connector_client = CVEConnectorClient(password=neo4j_password, bolt=neo4j_bolt, user=neo4j_user)
    try:
        versions_and_timestamps = cve_connector_client.get_all_software_versions()
    except Exception as e:
        logging.exception(f"Failed to retrieve software versions from Neo4j: {type(e).__name__}: {e}")
        raise

    if not versions_and_timestamps:
        logging.info("No software versions found in Neo4j database.")
        return "No software versions found in Neo4j database."

    logging.info(f"Versions {len(versions_and_timestamps)}")

    max_retries = 1
    retry_delay = 6

    def _parse_timestamp(timestamp: str | None) -> datetime | None:
        if not timestamp:
            return None
        try:
            return datetime.fromisoformat(timestamp)
        except ValueError:
            logging.warning(f"Invalid timestamp format in Neo4j: {timestamp!r}")
            return None

    for version_item in versions_and_timestamps:
        version = version_item.version
        timestamp = _parse_timestamp(version_item.cve_timestamp)
        cpe_item = CpeIdentifier.from_string(version_item.version)
        logging.info(f"Processing CVEs for version: {version}")
        cve_data: list[dict[str, object]] | None = None
        obtained_all_results = False
        start_index = 0
        while not obtained_all_results:
            raw_data: NvdCvesApiResponse | None = None
            for attempt in range(1, max_retries + 1):
                try:
                    raw_data = search_cve_by_version(
                        version=f"{cpe_item.vendor}:{cpe_item.product}:{cpe_item.version}",
                        part=cpe_item.part,
                        api_key=nvd_api_key,
                        start_index=start_index,
                        is_vulnerable=True,
                        last_mod_start_date=timestamp,
                    )
                    if raw_data is not None:
                        cve_data = [vuln.cve for vuln in raw_data.vulnerabilities]
                        logging.info(f"Found {len(cve_data)} vulnerabilities")
                    time.sleep(retry_delay)
                    if cve_data is not None:
                        break
                    logging.info(
                        f"API returned None for {version}, attempt {attempt}/{max_retries}. Retrying in {retry_delay}s..."
                    )

                except Exception as e:
                    time.sleep(retry_delay)
                    logging.exception(f"Error querying NVD API for {version}: {type(e).__name__}: {e}")
                    if attempt == max_retries:
                        logging.exception(f"Max retries reached for {version}. Skipping.")
                        break

            if cve_data is None:
                logging.error(f"Failed to retrieve CVEs for{version}) after {max_retries} attempts.")
                break

            if not cve_data:
                logging.info(f"No CVEs found for version: {version}")
                break

            parsed_data = parse_vulnerabilities(data=cve_data)
            logging.info(f"Successfully parsed {len(parsed_data)} CVEs")
            try:
                data_length = len(parsed_data)
                slice_start = 0
                slice_step = 100
                while slice_start <= data_length:
                    if slice_start + slice_step <= data_length:
                        move_cve_data_to_neo4j(
                            parsed_data[slice_start : slice_start + 100],
                            version,
                            neo4j_password,
                            neo4j_bolt,
                            neo4j_user,
                            nvd_api_key,
                        )
                    else:
                        move_cve_data_to_neo4j(
                            parsed_data[slice_start:data_length],
                            version,
                            neo4j_password,
                            neo4j_bolt,
                            neo4j_user,
                            nvd_api_key,
                        )
                    logging.info(f"Successfully updated Neo4j with CVEs for {version}, slice_start: {slice_start}")
                    slice_start += 100
            except Exception as e:
                logging.exception(f"Failed to update Neo4j for {version}: {type(e).__name__}: {e}")
                continue

            # TODO: Why was there start at 2000?
            if raw_data is None:
                obtained_all_results = True
            else:
                start = raw_data.startIndex or start_index
                per_page = raw_data.resultsPerPage or 0
                total = raw_data.totalResults or 0
                if per_page > 0 and start + per_page < total:
                    start_index = start + per_page
                else:
                    obtained_all_results = True

        cve_connector_client.update_timestamp_of_software_version(
            version,
            workflow_start.isoformat(),
        )
    return f"Executed CVE download for {len(versions_and_timestamps)} software versions."


def _get_neo4j_connection_settings(config: Config) -> tuple[str, str, str]:
    return (
        os.getenv("NEO4J_PASSWORD") or config.neo4j.password,
        os.getenv("NEO4J_BOLT") or config.neo4j.bolt,
        os.getenv("NEO4J_USER") or config.neo4j.user,
    )


class CveDatabaseUpdater:
    def run_database_update(self, workflow_start: datetime) -> None:
        """
        Executes the CVE version update process.

        Calls cve_version to fetch, parse, and update CVE data in Neo4j.

        :param workflow_start: Timestamp when the workflow started.
        :return: None
        :raises Exception: If Neo4j operations fail due to connection or query issues.
        :raises KeyError: If required environment variables are missing.
        """
        config = AppConfig.get()
        cve_config = config.cve_connector
        neo4j_password, neo4j_bolt, neo4j_user = _get_neo4j_connection_settings(config)

        logging.info(f"NVD API KEY: {cve_config.nvd_api_key}")

        cve_version(
            workflow_start,
            neo4j_password=neo4j_password,
            neo4j_bolt=neo4j_bolt,
            neo4j_user=neo4j_user,
            nvd_api_key=cve_config.nvd_api_key or os.getenv("NVD_KEY", ""),
        )


class CveUpdateActivities:
    def __init__(self, db_client: CveDatabaseUpdater) -> None:
        """
        Initializes the CveUpdateActivities class with a database updater.

        :param db_client: Instance of CveDatabaseUpdater for database operations.
        :return: None
        """
        self.db_client = db_client

    @activity.defn
    async def do_database_thing(self, workflow_start: datetime) -> None:
        """
        Temporal activity to perform CVE database updates.

        Executes the run_database_update method of the database updater.

        :param workflow_start: Timestamp when the workflow started.
        :return: None
        :raises Exception: If Neo4j operations fail due to connection or query issues.
        :raises KeyError: If required environment variables are missing.
        """
        self.db_client.run_database_update(workflow_start)


@workflow.defn
class CveUpdateWorkflow:
    @workflow.run
    async def run(self) -> None:
        """
        Temporal workflow to execute the CVE database update activity.

        Schedules the do_database_thing activity with a timeout.

        :return: None
        :raises temporalio.exceptions.ActivityError: If the activity fails.
        """
        await workflow.execute_activity(
            CveUpdateActivities.do_database_thing,
            workflow.now(),
            start_to_close_timeout=timedelta(hours=1, minutes=30),
            retry_policy=RetryPolicy(
                maximum_attempts=1,
            ),
        )


async def main() -> None:
    """
    Sets up and runs the Temporal client, schedule, and worker for CVE updates.

    Connects to the Temporal server, creates a schedule if it doesn't exist, and runs a worker
    to execute the CveUpdateWorkflow. Handles shutdown signals gracefully.

    :return: None
    :raises ConnectionRefusedError: If connection to Temporal server fails after retries.
    :raises KeyError: If required environment variables are missing.
    """
    config = AppConfig.get()
    _, neo4j_bolt, neo4j_user = _get_neo4j_connection_settings(config)

    required_env_vars = ["TEMPORAL_HOST", "TEMPORAL_PORT"]
    for env_var in required_env_vars:
        if not os.getenv(env_var):
            logging.error(f"Missing required environment variable: {env_var}")
            raise KeyError(f"Missing environment variable: {env_var}")

    logging.info(f"Using Neo4j bolt endpoint {neo4j_bolt} with user {neo4j_user}")

    max_retries = 20
    retry_interval = 10
    temporal_address = f"{os.getenv('TEMPORAL_HOST')}:{os.getenv('TEMPORAL_PORT')}"

    client: Client | None = None
    for attempt in range(1, max_retries + 1):
        try:
            client = await Client.connect(temporal_address)
            logging.info(f"Successfully connected to Temporal server on attempt {attempt}")
            break
        except ConnectionRefusedError as e:
            logging.warning(f"Connection refused on attempt {attempt}/{max_retries}: {e}")
            if attempt == max_retries:
                logging.exception("Max retries reached. Could not connect to Temporal server.")
                raise ConnectionRefusedError("Failed to connect to Temporal server") from e
            await asyncio.sleep(retry_interval)
        except Exception as e:
            logging.warning(f"Unexpected error on attempt {attempt}/{max_retries}: {e}")
            if attempt == max_retries:
                logging.exception("Max retries reached. Could not connect to Temporal server.")
                raise
            await asyncio.sleep(retry_interval)

    if client is None:
        raise ConnectionRefusedError("Failed to connect to Temporal server")

    schedule_id = "cve-update-scheduled-workflow"
    try:
        async for schedule_item in await client.list_schedules():
            if schedule_item.id == schedule_id:
                raise ScheduleAlreadyRunningError()

        schedule = Schedule(
            action=ScheduleActionStartWorkflow(
                CveUpdateWorkflow.run,
                id="cve-update-workflow-instance",
                task_queue="cve-update-task-queue",
            ),
            spec=ScheduleSpec(intervals=[ScheduleIntervalSpec(every=timedelta(hours=2))]),
        )
        await client.create_schedule(schedule_id, schedule)
        logging.info(f"Schedule: {schedule_id} created.")
    except ScheduleAlreadyRunningError:
        logging.info(f"Schedule {schedule_id} already running.")
    except TemporalError as e:
        logging.info(f"Temporal error: {e}. Schedule creation failed.")

    db_client = CveDatabaseUpdater()
    activities = CveUpdateActivities(db_client)

    shutdown_event = asyncio.Event()

    def handle_shutdown(loop: asyncio.AbstractEventLoop, event: asyncio.Event) -> None:
        """
        Handles shutdown signals by setting the shutdown event.

        :param loop: Event loop handling the signals.
        :param event: Shutdown event to signal worker termination.
        :return: None
        """
        logging.info("Received shutdown signal, initiating graceful shutdown...")
        event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_shutdown, loop, shutdown_event)

    logging.info("Starting Temporal Worker...")

    redis_handler.init_redis()

    worker = Worker(
        client,
        task_queue="cve-update-task-queue",
        workflows=[CveUpdateWorkflow],
        activities=[activities.do_database_thing],
        workflow_runner=UnsandboxedWorkflowRunner(),
    )

    async with worker:
        try:
            await shutdown_event.wait()
        except asyncio.CancelledError:
            logging.info("Worker cancelled")
        finally:
            logging.info("Worker stopped gracefully")


if __name__ == "__main__":
    asyncio.run(main())
