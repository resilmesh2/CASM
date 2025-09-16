import uuid

from redis import Redis

from config import RedisConfig
from temporal.lib import exceptions, util
from temporal.lib.exceptions import NoDomainsFoundError


async def run_subfinder(domains: list[str], redis_config: RedisConfig) -> str:

    subfinder_scan_uuid: str = uuid.uuid4().hex

    command = ["subfinder", "-d", *domains, "-silent"]

    std_out, std_err, return_code = await util.run_command_with_output(command)

    if return_code != 0:
        raise exceptions.EnumerationToolError(f"subfinder run failed with status code {return_code} and error {std_err}, command={command}",)

    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    redis_client.set(subfinder_scan_uuid, std_out)
    redis_client.close()

    return subfinder_scan_uuid


async def run_amass(domains: list[str], redis_config: RedisConfig) -> str:

    amass_scan_uuid: str = uuid.uuid4().hex

    command = ["amass", "enum", "-d", *domains, "-passive"]

    std_out, std_err, return_code = await util.run_command_with_output(command)

    if return_code != 0:
        raise exceptions.EnumerationToolError(f"amass run failed with status code {return_code} and error {std_err}, command={command}",)

    # Store results in Redis
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    redis_client.set(amass_scan_uuid, std_out)
    redis_client.close()

    return amass_scan_uuid


async def get_unique_subdomains(redis_config: RedisConfig, data_redis_uuids: list[str]) -> str:
    unique_subdomains = set()
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    for uuid_item in data_redis_uuids:
        data = redis_client.get(uuid_item)
        if data:
            unique_subdomains.update(data.decode("utf-8").splitlines())

    str_unique_subdomains = "\n".join(unique_subdomains)

    if not str_unique_subdomains:
        redis_client.close()
        raise NoDomainsFoundError("subfinder and amass did not find any domains")

    unique_subdomains_uuid = f"unique_subdomains-{uuid.uuid4()!s}"
    redis_client.set(unique_subdomains_uuid, str_unique_subdomains)
    redis_client.close()
    return unique_subdomains_uuid
