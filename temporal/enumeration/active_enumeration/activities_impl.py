import asyncio
import json
import tempfile
import uuid

from redis import Redis

from config import RedisConfig
from temporal.lib import util
from temporal.lib.util import get_unique_subdomains
from temporalio import activity


async def active_dnsx(passive_scan_domains_uuid: str, wordlist: str, redis_config: RedisConfig) -> str:
    """
    Brute-force subdomains via dnsx wordlist approach.
    Store results in Redis.
    """
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    domains = redis_client.get(passive_scan_domains_uuid).splitlines()

    command = ["dnsx", "-d", *domains, "-silent", "-w", wordlist, "-a", "-cname", "-aaaa"]

    std_out, _std_err, _status_code = await util.run_command_with_output(command)

    dnsx_unique_result = get_unique_subdomains(std_out)

    dnsx_uuid = f"dnsx-{str(uuid.uuid4())}"
    redis_client.set(dnsx_uuid, dnsx_unique_result)
    redis_client.close()

    return dnsx_uuid


async def active_alterx(domains_uuid: str, redis_config: RedisConfig) -> str:
    """
    Permutation scan + DNS resolution.
    Store results in Redis.
    """

    # Get input domains from Redisn
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    input_domains = redis_client.get(domains_uuid)

    if not input_domains:
        redis_client.close()
        return ""

    # Write Redis data to temporary file
    with tempfile.NamedTemporaryFile(mode="w") as alterx_domains:
        with tempfile.NamedTemporaryFile(mode="w") as domains_file:
            domains_file.write(input_domains.decode("utf-8"))
            alterx_command = ["alterx", "-l", domains_file.name, "-silent", "-o", alterx_domains]
            process = await asyncio.create_subprocess_exec(*alterx_command)
            await process.communicate()

        dnsx_command = ["dnsx", "-l", alterx_domains.name, "-silent", "-a", "-aaaa", "-cname"]
        std_out, _std_err, _return_code = await util.run_command_with_output(dnsx_command)

    # Read results and store back in Redis

    alterx_uuid = f"alterx-{str(uuid.uuid4())}"
    redis_client.set(alterx_uuid, std_out)

    redis_client.close()

    return alterx_uuid


@activity.defn
async def active_httpx(alterx_domains_uuid: str, redis_config: RedisConfig) -> str:
    """
    Run httpx over a list of domains (active scanning).
    Store results in Redis.
    """

    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    input_data = redis_client.get(alterx_domains_uuid)

    if not input_data:
        redis_client.close()
        return ""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
        temp_file.write(input_data.decode("utf-8"))
        temp_input = temp_file.name

    # Run httpx command and capture JSON output directly
        command = ["/home/harwin/go/bin/httpx", "-l", temp_input, "-silent", "-td", "-j"]
        stdout, _stderr, return_code = await util.run_command_with_output(command)

    if return_code != 0:
        return ""

    # Define fields to keep
    fields_to_keep = [
        "timestamp",
        "port",
        "url",
        "input",
        "title",
        "scheme",
        "webserver",
        "content_type",
        "method",
        "host",
        "path",
        "time",
        "a",
        "tech",
        "words",
        "lines",
        "status_code",
        "content_length",
        "failed",
    ]

    # Filter JSON output
    filtered_json = _filter_httpx_json_string(stdout, fields_to_keep)

    # Store results in Redis
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    httpx_uuid = f"httpx-{str(uuid.uuid4())}"
    redis_client.set(httpx_uuid, filtered_json)

    return httpx_uuid


def _filter_httpx_json_string(json_input: str, fields_to_keep: list[str]) -> str:
    results = []

    for line in json_input.strip().split("\n"):
        if line.strip():
            try:
                json_obj = json.loads(line)
                # Extract only the fields we want to keep
                filtered_obj = {field: json_obj.get(field) for field in fields_to_keep if field in json_obj}
                results.append(filtered_obj)
            except json.JSONDecodeError:
                continue

    return json.dumps(results, indent=2)
