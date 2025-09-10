import asyncio
import uuid

from redis import Redis

from config import RedisConfig


async def run_subfinder(domains: list[str], redis_config: RedisConfig) -> str:

    subfinder_scan_uuid: str = uuid.uuid4().hex

    command = ["subfinder", "-d", *domains, "-silent"]

    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    result = stdout.decode("utf-8")

    if stderr:
        stderr.decode("utf-8")

    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    redis_client.set(subfinder_scan_uuid, result)
    redis_client.close()

    return subfinder_scan_uuid


async def run_amass(domains: list[str], redis_config: RedisConfig) -> str:

    amass_scan_uuid: str = uuid.uuid4().hex

    command = ["amass", "enum", "-d", *domains, "-passive"]

    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    result = stdout.decode("utf-8")

    if stderr:
        stderr.decode("utf-8")

    # Store results in Redis
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    redis_client.set(amass_scan_uuid, result)
    redis_client.close()

    return amass_scan_uuid
