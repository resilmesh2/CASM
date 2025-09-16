import asyncio
import tempfile
import uuid

from redis import Redis

from config import RedisConfig
from temporal.lib import exceptions, util


async def run_dnsx_bruteforce(passive_scan_domains_uuid: str, wordlist: str, threads: str, redis_config: RedisConfig) -> str:
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    domains = redis_client.get(passive_scan_domains_uuid).decode("utf-8")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as domain_temp_file:
        domain_temp_file.write(domains)

        command = ["dnsx", "-d", domain_temp_file.name, "-silent", "-w", wordlist, "-a", "-cname", "-aaaa", "t", threads]
        std_out, std_err, return_code = await util.run_command_with_output(command)

    if return_code != 0:
        redis_client.close()
        raise exceptions.EnumerationToolError(f"dnsx run failed with status code {return_code} and error {std_err}, command={command}",)
    if not std_out:
        redis_client.close()
        raise exceptions.NoDomainsFoundError(f"dnsx bruteforce returned no results, command={command}")

    dnsx_unique_result = util.get_unique_subdomains(std_out)
    dnsx_uuid = f"dnsx-bruteforce-{uuid.uuid4()!s}"
    redis_client.set(dnsx_uuid, dnsx_unique_result)
    redis_client.close()

    return dnsx_uuid


async def run_alterx(domains_uuid: str, redis_config: RedisConfig) -> str:
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    input_domains = redis_client.get(domains_uuid).decode("utf-8")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as domains_file, tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as alterx_output:
        domains_file.write(input_domains)
        domains_file.flush()

        alterx_command = ["alterx", "-l", domains_file.name, "-silent", "-o", alterx_output.name]
        process = await asyncio.create_subprocess_exec(*alterx_command)
        return_code = await process.wait()

        if return_code != 0:
            redis_client.close()
            raise exceptions.EnumerationToolError(
                f"alterx run failed with status code {return_code}, command={alterx_command}"
            )

        alterx_output.seek(0)
        alterx_results = alterx_output.read()

    alterx_uuid = f"alterx-{uuid.uuid4()!s}"
    redis_client.set(alterx_uuid, alterx_results)
    redis_client.close()

    return alterx_uuid


async def run_dnsx_resolver(domains_uuid: str, redis_config: RedisConfig) -> str:
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    input_domains = redis_client.get(domains_uuid).decode("utf-8")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as domains_file:
        domains_file.write(input_domains)
        domains_file.flush()

        dnsx_command = ["dnsx", "-l", domains_file.name, "-silent", "-a", "-aaaa", "-cname"]
        std_out, std_err, return_code = await util.run_command_with_output(dnsx_command)

    if return_code != 0:
        redis_client.close()
        raise exceptions.EnumerationToolError(
            f"dnsx run failed with status code {return_code} and error {std_err}, command={dnsx_command}"
        )
    if not std_out:
        redis_client.close()
        raise exceptions.NoDomainsFoundError(f"dnsx resolver returned no results, command={dnsx_command}")

    dnsx_unique_result = util.get_unique_subdomains(std_out)
    dnsx_resolver_uuid = f"dnsx-resolver-{uuid.uuid4()!s}"
    redis_client.set(dnsx_resolver_uuid, dnsx_unique_result)
    redis_client.close()

    return dnsx_resolver_uuid
