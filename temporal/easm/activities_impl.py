import json
import tempfile
import urllib
import uuid
from dataclasses import asdict, dataclass
from ipaddress import IPv4Interface, IPv6Interface
from typing import Any

from redis import Redis

from config import RedisConfig
from temporal.lib import exceptions, util


@dataclass
class EasyEASMParsedResult:
    """
    Container for a single parsed httpx result used by the EASM pipeline.

    :param port: TCP port observed for the service (e.g., 80, 443).
    :param protocol: Application protocol/scheme as reported by httpx (e.g., http, https).
    :param service: Human-readable service name (often same as protocol for httpx results).
    :param ip: Resolved IP address for the host, if available.
    :param domain_name: Input domain or hostname that was probed.
    :param software_versions: Optional list of detected technologies mapped to CPEs, each item
                              being a mapping with keys "name" and "version".
    """

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


async def run_httpx(domains_to_probe_uuid: str, httpx_path: str, redis_config: RedisConfig) -> str:
    """
    Execute the external httpx tool over domains loaded from Redis and store its output.

    The function reads newline-separated domains from Redis using the provided
    UUID key, writes them temporarily to a file, and runs the httpx binary with
    JSON output enabled. The resulting JSON Lines (one JSON object per line) is
    persisted back to Redis under a new key which is returned.

    :param domains_to_probe_uuid: Redis key holding the input domains (newline-separated).
    :param httpx_path: Path to the httpx executable to invoke.
    :param redis_config: Connection details for Redis.
    :return: Redis key where the httpx JSONL output is stored.
    :raises temporal.lib.exceptions.EnumerationToolError: If the httpx command returns a non-zero exit code.
    """
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    input_data = redis_client.get(domains_to_probe_uuid).decode("utf-8")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
        temp_file.write(input_data)
        temp_input = temp_file.name

        command = [httpx_path, "-l", temp_input, "-silent", "-td", "-j"]
        std_out, std_err, return_code = await util.run_command_with_output(command)

    if return_code != 0:
        redis_client.close()
        raise exceptions.EnumerationToolError(
            f"httpx run failed with status code {return_code} and error {std_err, std_out}, command={command}",
        )

    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    httpx_uuid = f"httpx-{uuid.uuid4()!s}"
    redis_client.set(httpx_uuid, std_out)
    redis_client.close()

    return httpx_uuid


def parse_httpx_output(httpx_uuid: str, redis_config: RedisConfig) -> list[EasyEASMParsedResult]:
    """
    Parse httpx JSON Lines stored in Redis into typed EasyEASMParsedResult objects.

    :param httpx_uuid: Redis key where httpx JSONL output is stored.
    :param redis_config: Connection details for Redis.
    :return: List of parsed results, one per successful httpx line entry.
    """
    redis_client = Redis(host=redis_config.host, port=redis_config.port, db=0)
    httpx_json = redis_client.get(httpx_uuid).decode("utf-8")
    redis_client.close()
    easm_output: list[EasyEASMParsedResult] = []

    for line in httpx_json.strip().split("\n"):
        if not line.strip():
            continue

        json_obj = json.loads(line)

        if json_obj.get("failed", False):
            continue

        host_ip = json_obj.get("host", "")
        input_domain = json_obj.get("input", "")
        port = json_obj.get("port", 80)
        scheme = json_obj.get("scheme", "http")
        tech_list = json_obj.get("tech", [])

        easm_output.append(
            EasyEASMParsedResult(
                port=port,
                protocol=scheme,
                service=scheme,
                ip=host_ip,
                domain_name=input_domain,
                software_versions=determine_software_versions(tech_list),
            )
        )

    return easm_output


WAPPALYZERGO_FINGERPRINTS_URL = (
    "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json"
)


def determine_software_versions(technologies: list[str]) -> list[dict[str, str]]:
    """
    Map detected technology strings to normalized CPE entries using wappalyzergo fingerprints.

    Each technology string may optionally contain a version after a colon, e.g.,
    "Apache:httpd 2.4". If a CPE template exists for the technology, a concrete
    CPE 2.3 string is produced with the detected version or a wildcard.

    :param technologies: List of technology identifiers returned by httpx (items like
                         "nginx:1.24" or "Apache").
    :return: A list of dictionaries with keys:
             - "name": Original technology string from input.
             - "version": A CPE 2.3 string reflecting vendor, product, and version.
    """
    if not technologies:
        return []

    with urllib.request.urlopen(WAPPALYZERGO_FINGERPRINTS_URL) as jsonfile:
        fingerprints = json.load(jsonfile)

    results = []

    for tech in technologies:
        name, version = ([*tech.split(":", 1), None])[:2]
        name, version = name.strip(), (version.strip() if version else None)

        if name in fingerprints["apps"]:
            app_data = fingerprints["apps"][name]
            if "cpe" in app_data:
                vendor, product = app_data["cpe"].split(":")[3:5]
                cpe_version = version or "*"
                cpe = f"cpe:2.3:a:{vendor}:{product}:{cpe_version}:*:*:*:*:*:*:*"
                entry = {"name": tech, "version": cpe}

                if entry not in results:
                    results.append(entry)

    return results
