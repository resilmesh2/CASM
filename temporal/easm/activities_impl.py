import json
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from ipaddress import IPv4Interface, IPv6Interface
from typing import Any, TypedDict

import httpx

from temporal.lib import exceptions, redis_handler, util


class AppData(TypedDict, total=False):
    cpe: str  # e.g. "cpe:2.3:a:vendor:product" or "cpe:/a:vendor:product"


class Fingerprints(TypedDict):
    apps: dict[str, AppData]


class OutputEntry(TypedDict):
    name: str  # original input token (e.g., "Apache:httpd 2.4" or "nginx:1.24")
    version: str  # concrete CPE 2.3 string


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
    software_versions: list[OutputEntry] = field(default_factory=list[OutputEntry])
    ip: IPv4Interface | IPv6Interface | None = None
    domain_name: str | None = None

    def __post_init__(self) -> None:
        if self.ip is None and self.domain_name is None:
            raise ValueError("Either IP or domain is necessary!")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def run_httpx(domains_to_probe_uuid: str, httpx_path: str) -> str:
    """
    Execute the external httpx tool over domains loaded from Redis and store its output.

    The function reads newline-separated domains from Redis using the provided
    UUID key, writes them temporarily to a file, and runs the httpx binary with
    JSON output enabled. The resulting JSON Lines (one JSON object per line) is
    persisted back to Redis under a new key which is returned.

    :param domains_to_probe_uuid: Redis key holding the input domains (newline-separated).
    :param httpx_path: Path to the httpx executable to invoke.
    :return: Redis key where the httpx JSONL output is stored.
    :raises temporal.lib.exceptions.EnumerationToolError: If the httpx command returns a non-zero exit code.
    """
    redis_client = redis_handler.get_redis()
    input_data = redis_client.get(domains_to_probe_uuid)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as temp_file:
        temp_file.write(str(input_data))
        temp_file.flush()
        temp_input = temp_file.name

        command = [httpx_path, "-l", temp_input, "-silent", "-td", "-j"]
        std_out, std_err, return_code = await util.run_command_with_output(command)
        temp_file.close()

    if return_code != 0:
        redis_client.close()
        raise exceptions.EnumerationToolError(
            f"httpx run failed with status code {return_code} and error {std_err, std_out}, command={command}",
        )

    httpx_uuid = f"httpx-{uuid.uuid4()!s}"
    output_data = std_out + std_err
    redis_client.set(httpx_uuid, output_data)

    return httpx_uuid


def parse_httpx_output(httpx_uuid: str) -> list[EasyEASMParsedResult]:
    """
    Parse httpx JSON Lines stored in Redis into typed EasyEASMParsedResult objects.

    :param httpx_uuid: Redis key where httpx JSONL output is stored.
    :return: List of parsed results, one per successful httpx line entry.
    """
    redis_client = redis_handler.get_redis()
    httpx_json = str(redis_client.get(httpx_uuid))
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


def fetch_fingerprints(url: str = WAPPALYZERGO_FINGERPRINTS_URL, timeout_s: float = 10.0) -> Fingerprints:
    """
    Download the WappalyzerGo fingerprints database and return it as a mapping.

    The returned structure is expected to contain an "apps" dictionary with
    entries describing technologies (apps) and, when available, a "cpe" field
    that identifies the technology using a CPE string. Only a tiny portion of
    the full schema is modeled here because we only need the CPE field.

    :param url: HTTP URL of the fingerprints JSON file to download.
    :param timeout_s: Total HTTP client timeout in seconds.
    :return: Parsed JSON body as a Fingerprints dict.
    :raises httpx.HTTPError: If the request fails or returns a bad status.
    """
    with httpx.Client(timeout=httpx.Timeout(timeout_s)) as client:
        r = client.get(url)
        r.raise_for_status()
        return r.json()


def _split_name_version(token: str) -> tuple[str, str | None]:
    """
    Split a technology token into name and version parts.

    Tokens are expected in the form "name:version" (e.g., "nginx:1.24"). If no
    colon is present, the entire token is treated as the name and the version is
    returned as None.

    :param token: Technology token reported by httpx/wappalyzer (e.g., "Apache:httpd 2.4" or "nginx:1.24").
    :return: Tuple of (name, version_or_none).
    """
    if ":" not in token:
        return token.strip(), None

    name, version = token.split(":", 1)
    return name.strip(), version.strip()


def _parse_vendor_product_from_cpe(cpe: str) -> tuple[str, str] | None:
    """
    Extract vendor and product from a CPE string.

    Supports the two common forms encountered in the fingerprints:
    - "cpe:2.3:a:vendor:product[:...]"
    - "cpe:/a:vendor:product[:...]"

    The function finds the segment after the "a" part indicator and returns the
    next two fields as (vendor, product). If the string does not match the
    expected structure, None is returned.

    :param cpe: Input CPE string from the fingerprints database.
    :return: (vendor, product) tuple or None if parsing fails.
    """
    parts = cpe.split(":")
    if len(parts) < 4:
        return None

    # For both formats, vendor and product follow the 'a' part indicator
    # cpe:2.3:a:vendor:product or cpe:/a:vendor:product
    try:
        a_index = parts.index("a")
        if a_index + 2 < len(parts):
            vendor = parts[a_index + 1].strip()
            product = parts[a_index + 2].strip()
            if vendor and product:
                return vendor, product
    except ValueError:
        pass

    return None


def _make_cpe23_app(vendor: str, product: str, version: str | None) -> str:
    """
    Build a CPE 2.3 application string for the given vendor/product/version.

    When version is None or empty, a wildcard "*" is used in the version slot.
    All other CPE 2.3 fields are filled with "*" since they are not needed for
    the current use case.

    :param vendor: CPE vendor field.
    :param product: CPE product field.
    :param version: Optional product version; if None, a wildcard is used.
    :return: A normalized CPE 2.3 string, e.g., "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*".
    """
    v = version or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


def determine_software_versions(technologies: list[str]) -> list[OutputEntry]:
    """
    Convert detected technology tokens into concrete CPE 2.3 strings.

    For each token in the input list (e.g., "nginx:1.24" or "Apache:httpd 2.4"),
    this function:
    - Splits it into name and optional version.
    - Looks up the technology in the WappalyzerGo fingerprints to find a base CPE.
    - Parses vendor and product from that CPE.
    - Builds a full CPE 2.3 app string using the detected version or a wildcard.

    Duplicate (token, CPE) pairs are deduplicated in the output.

    :param technologies: List of technology tokens reported by httpx/wappalyzer.
    :return: List of mappings with keys:
             - "name": the original token from input
             - "version": the computed CPE 2.3 string
    """
    if not technologies:
        return []

    fingerprints = fetch_fingerprints()
    apps = fingerprints.get("apps", {})

    results: list[OutputEntry] = []
    seen: set[tuple[str, str]] = set()

    for token in technologies:
        name, version = _split_name_version(token)

        app = apps.get(name)
        if not app or "cpe" not in app:
            continue

        vendor_product = _parse_vendor_product_from_cpe(app["cpe"])
        if not vendor_product:
            continue

        vendor, product = vendor_product
        cpe23 = _make_cpe23_app(vendor, product, version)

        key = (token, cpe23)
        if key not in seen:
            seen.add(key)
            results.append({"name": token, "version": cpe23})

    return results
