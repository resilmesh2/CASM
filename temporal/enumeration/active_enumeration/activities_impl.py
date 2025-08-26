import asyncio
import json
import tempfile
import uuid

from redis import Redis

from config import RedisConfig
from temporal.lib import util
from temporal.lib.util import get_unique_subdomains
from temporalio import activity


async def active_dnsx(domains: list[str], wordlist: str, redis_config: RedisConfig) -> str:
    """
    Brute-force subdomains via dnsx wordlist approach.
    Store results in Redis.
    """
    # Generate a unique scan_uuid
    dnsx_uuid = str(uuid.uuid4())

    # Run dnsx command
    command = ["dnsx", "-d", *domains, "-silent", "-w", wordlist, "-a", "-cname", "-aaaa"]
    print("Running command: ", *command)

    # Run the process without blocking the worker
    std_out, std_err, status_code = util.run_command_with_output(command)

    dnsx_unique_result = get_unique_subdomains(std_out)
    # Store results in Redis
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    await redis_client.set(dnsx_uuid, dnsx_unique_result)
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
        print(f"No input data found in Redis for domains_uuid: {domains_uuid}")
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
        std_out, std_err, return_code = await util.run_command_with_output(dnsx_command)

    # Read results and store back in Redis

    alterx_uuid = str(uuid.uuid4())
    await redis_client.set(alterx_uuid, std_out)

    redis_client.close()

    return alterx_uuid

@activity.defn
async def active_httpx(alterx_domains_uuid: str, redis_config: RedisConfig) -> str:
    """
    Run httpx over a list of domains (active scanning).
    Store results in Redis.
    """
    # Generate a unique scan_uuid
    httpx_uuid = str(uuid.uuid4())

    # Get input domains from Redis
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    input_data = redis_client.get(alterx_domains_uuid)

    if not input_data:
        print(f"No domains found in Redis for httpx: {alterx_domains_uuid}")
        redis_client.close()
        return ""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt') as temp_file:
        temp_file.write(input_data.decode("utf-8"))
        temp_input = temp_file.name

    # Run httpx command and capture JSON output directly
        command = ["/home/harwin/go/bin/httpx", "-l", temp_input, "-silent", "-td", "-j"]
        stdout, stderr, return_code = await util.run_command_with_output(command)

    if return_code != 0:
        print(f"httpx failed with return code {return_code}: {stderr}")
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
    await redis_client.set(httpx_uuid, filtered_json)

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
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON line: {e}")
                continue

    return json.dumps(results, indent=2)
