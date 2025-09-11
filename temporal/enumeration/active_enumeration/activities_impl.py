import asyncio
import json
import tempfile
import urllib
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from ipaddress import IPv4Interface, IPv6Interface
from typing import Any

from redis import Redis

from config import RedisConfig
from temporal.lib import util
from temporal.lib.util import get_unique_subdomains
from temporalio import activity


@dataclass
class EasyEASMParsedResult:
    port: int
    protocol: str
    service: str
    ip: IPv4Interface | IPv6Interface | None = None
    domain_name: str | None = None
    software_versions: list[dict[str, str]] | None = None

    def __post_init__(self) -> None:
        if self.ip is None and self.domain_name is None:
            raise ValueError("Either IP or domain is necessary!")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def run_dnsx(passive_scan_domains_uuid: str, wordlist: str, redis_config: RedisConfig) -> str:
    """ Back
    Brute-force subdomains via dnsx wordlist approach.
    Store results in Redis.
    """
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    domains = redis_client.get(passive_scan_domains_uuid).decode("utf-8")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as domain_temp_file:
        domain_temp_file.write(domains)

        command = ["dnsx", "-d", domain_temp_file.name, "-silent", "-w", wordlist, "-a", "-cname", "-aaaa"]
        std_out, _std_err, _status_code = await util.run_command_with_output(command)

    if not std_out:
        raise RuntimeError(f"Failed to get results from {command}")

    dnsx_unique_result = get_unique_subdomains(std_out)
    dnsx_uuid = f"dnsx-{str(uuid.uuid4())}"
    redis_client.set(dnsx_uuid, dnsx_unique_result)
    redis_client.close()

    return dnsx_uuid


async def run_alterx_with_dnsx(domains_uuid: str, redis_config: RedisConfig) -> str:
    """
    Permutation scan + DNS resolution.
    Store results in Redis.
    """

    # Get input domains from Redisn
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    input_domains = redis_client.get(domains_uuid).decode("utf-8")

    # Write Redis data to temporary file
    with tempfile.NamedTemporaryFile(mode="w") as alterx_domains:
        with tempfile.NamedTemporaryFile(mode="w") as domains_file:
            domains_file.write(input_domains)
            alterx_command = ["alterx", "-l", domains_file.name, "-silent", "-o", alterx_domains.name]
            process = await asyncio.create_subprocess_exec(*alterx_command)
            await process.communicate()

        dnsx_command = ["dnsx", "-l", alterx_domains.name, "-silent", "-a", "-aaaa", "-cname"]
        std_out, _std_err, _return_code = await util.run_command_with_output(dnsx_command)

    # Read results and store back in Redis
    if not std_out:
        raise RuntimeError(f"Failed to get results from {dnsx_command}")

    alterx_uuid = f"dnsx-with-alterx-{str(uuid.uuid4())}"
    redis_client.set(alterx_uuid, std_out)
    redis_client.close()

    return alterx_uuid


async def run_httpx(alterx_domains_uuid: str, redis_config: RedisConfig) -> str:
    """
    Run httpx over a list of domains (active scanning).
    Store raw JSON results in Redis.
    """
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    input_data = redis_client.get(alterx_domains_uuid).decode("utf-8")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
        temp_file.write(input_data)
        temp_input = temp_file.name

        # Run httpx command and capture JSON output directly
        command = ["/home/harwin/go/bin/httpx", "-l", temp_input, "-silent", "-td", "-j"]
        stdout, _stderr, return_code = await util.run_command_with_output(command)

    if return_code != 0:
        return ""

    # Store raw JSON results in Redis
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    httpx_uuid = f"httpx-{str(uuid.uuid4())}"
    redis_client.set(httpx_uuid, stdout)  # Store raw JSON output
    redis_client.close()

    return httpx_uuid


async def parse_httpx_output(httpx_uuid: str, redis_config: RedisConfig) -> list[EasyEASMParsedResult]:
    """
    Parse httpx JSON output into Host and SoftwareVersion dataclasses.
    """
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    httpx_json = redis_client.get(httpx_uuid).decode("utf-8")
    redis_client.close()
    easm_output: list[EasyEASMParsedResult] = []

    for line in httpx_json.strip().split("\n"):
        if not line.strip():
            continue

        json_obj = json.loads(line)

        # Skip failed requests
        if json_obj.get("failed", False):
            continue

        # Extract fields
        host_ip = json_obj.get("host", "")
        input_domain = json_obj.get("input", "")
        port = json_obj.get("port", 80)
        scheme = json_obj.get("scheme", "http")
        tech_list = json_obj.get("tech", [])

        easm_output.append(EasyEASMParsedResult(port=port, protocol=scheme, service=scheme, ip=host_ip, domain_name=input_domain, software_versions=determine_software_versions(tech_list)))

    return easm_output


WAPPALYZERGO_FINGERPRINTS_URL = "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json"


def determine_software_versions(technologies: list[str]) -> list[dict[str, str]]:
    """Parse technology list into CPE 2.3 software versions."""
    if not technologies:
        return []

    with urllib.request.urlopen(WAPPALYZERGO_FINGERPRINTS_URL) as jsonfile:
        fingerprints = json.load(jsonfile)

    results = []

    for tech in technologies:
        name, version = (tech.split(":", 1) + [None])[:2]
        name, version = name.strip(), (version.strip() if version else None)

        if name in fingerprints["apps"]:
            app_data = fingerprints["apps"][name]
            if "cpe" in app_data:
                vendor, product = app_data["cpe"].split(":")[3:5]
                cpe_version = version if version else "*"
                cpe = f"cpe:2.3:a:{vendor}:{product}:{cpe_version}:*:*:*:*:*:*:*"
                entry = {"name": tech, "version": cpe}

                if entry not in results:
                    results.append(entry)

    return results


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
