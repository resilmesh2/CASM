import asyncio

from temporalio.client import (
    Client,
)
from temporalio.worker import Worker

from component_calculation import ComponentCalculationWorkflow, RiskFormulaCalculationWorkflow, logger


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
