import json
import logging
import uuid
from dataclasses import asdict
from enum import Enum
from pathlib import Path

import dacite
import httpx
from valkey import Valkey

from config import ISIMUrlsConfig
from temporal.lib import util
from temporal.nuclei import dtos, exceptions

logger = logging.getLogger(__name__)

# Template directory paths
NUCLEI_TEMPLATE_DIR = Path("/root/nuclei-templates")
HTTP_CVE_TEMPLATES_PATH = NUCLEI_TEMPLATE_DIR / "http" / "cves"
NETWORK_CVE_TEMPLATES_PATH = NUCLEI_TEMPLATE_DIR / "network" / "cves"
NUCLEI_BINARY = "nuclei"

NUCLEI_OUTPUT_FILE = "nuclei_results.json"


class VulnerabilityStatus(Enum):
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    NOT_FOUND = "not_found"


async def get_network_service_data(isim_urls: ISIMUrlsConfig, valkey_client: Valkey) -> str:
    """
    Fetch network service data with CVEs from ISIM GraphQL API and store in Valkey.

    :param isim_urls: Configuration for ISIM GraphQL endpoint
    :param valkey_client: Valkey client for storing service data
    :return: UUID key for accessing stored service data in Valkey
    """
    query = (Path(__file__).parent / "assets" / "get_network_services_with_cves.graphql").read_text(encoding="utf-8")

    payload = {
        "query": query,
    }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(isim_urls.graphql_url, json=payload)
        resp.raise_for_status()
    service_data_uuid = f"service_data-{uuid.uuid4()!s}"

    valkey_client.set(service_data_uuid, resp.content.decode("utf-8"))

    return service_data_uuid


async def update_nuclei(nuclei_path: str | None = None) -> None:
    """
    Update Nuclei binary and templates to latest versions.

    :param nuclei_path: Optional custom path to nuclei binary directory
    :return: None
    :raises Exception: If nuclei update commands fail
    """
    nuclei_binary = "nuclei"
    if nuclei_path:
        nuclei_binary = f"{nuclei_path}/{nuclei_binary}"

    commands = [[nuclei_binary, "-update-templates"], [nuclei_binary, "-update"]]

    for command in commands:
        stdout, stderr, returncode = await util.run_command_with_output(command)
        logger.info(
            "Executed %s: returncode=%s stdout=%r stderr=%r",
            " ".join(command),
            returncode,
            stdout,
            stderr,
        )

        if returncode != 0:
            raise exceptions.NucleiRunError(f"Failed to update Nuclei templates/binary: returncode={returncode}")


def search_nuclei_templates(cve_id: str, service: str) -> list[str]:
    """
    Search for Nuclei templates matching a specific CVE ID and service type.

    :param cve_id: CVE identifier (e.g., 'CVE-2021-12345')
    :param service: Service name (e.g., 'http', 'ssh', 'ftp')
    :return: List of matching template file paths as strings
    :raises NucleiTemplatesNotFoundError: If nuclei template directories don't exist
    """
    matching_templates: list[str] = []

    # Determine which template paths to search
    search_paths = (
        [HTTP_CVE_TEMPLATES_PATH, NETWORK_CVE_TEMPLATES_PATH]
        if service.lower() == "http"
        else [NETWORK_CVE_TEMPLATES_PATH]
    )

    # Extract year from CVE ID (e.g., CVE-2021-12345 -> 2021)
    cve_parts = cve_id.split("-")
    cve_year = cve_parts[1] if len(cve_parts) >= 2 else None

    for search_path in search_paths:
        if not search_path.exists():
            raise exceptions.NucleiTemplatesNotFoundError

        # First, try direct file lookup by CVE ID in year subdirectory
        if cve_year:
            year_path = search_path / cve_year
            direct_template = year_path / f"{cve_id}.yaml"

            if direct_template.exists():
                matching_templates.append(str(direct_template))
                continue

        # If direct lookup fails, search all year subdirectories
        for year_dir in search_path.iterdir():
            if not year_dir.is_dir():
                continue

            # Look for exact CVE filename
            cve_template = year_dir / f"{cve_id}.yaml"
            if cve_template.exists():
                matching_templates.append(str(cve_template))
                break

    return matching_templates


def parse_data_for_nuclei_scan(valkey_client: Valkey, service_data_uuid: str) -> str:
    """
    Parse network service data and build a dictionary of services with matching Nuclei templates.

    :param valkey_client: Valkey client for retrieving and storing data
    :param service_data_uuid: UUID key for accessing service data in Valkey
    :return: UUID key for accessing parsed services with templates in Valkey
    """
    service_data_json = valkey_client.get(service_data_uuid)

    scan_data = dacite.from_dict(dtos.NetworkServiceData, json.loads(str(service_data_json))["data"])
    result: dict[str, dict[str, str | list[str]]] = {}

    for _host_idx, host in enumerate(scan_data.hosts):
        # Get primary domain name or IP
        target = "unknown"
        ip_address = "unknown"

        if host.node and host.node.ips:
            ip_obj = host.node.ips[0]
            ip_address = ip_obj.address
            target = ip_obj.domain_names[0].domain_name if ip_obj.domain_names else ip_address

        for service in host.network_services:
            service_key = f"{target}:{service.service}:{service.port}"
            all_templates: list[str] = []
            all_cves: list[str] = []

            # Collect all CVEs for this service
            for sw_version in service.software_versions:
                for vuln in sw_version.vulnerabilities:
                    cve_id = vuln.cve.cve_id
                    if cve_id:
                        all_cves.append(cve_id.upper())
                        templates = search_nuclei_templates(cve_id, service.service)
                        all_templates.extend(templates)

                        if templates:
                            logger.info(f"Found {len(templates)} template(s) for {cve_id}")

            # Remove duplicates
            all_templates = list(set(all_templates))
            all_cves = list(set(all_cves))

            result[service_key] = asdict(
                dtos.ServiceTemplateData(
                    target=target,
                    ip_address=ip_address,
                    port=service.port,
                    service=service.service,
                    protocol=service.protocol,
                    cves=all_cves,
                    templates=all_templates,
                )
            )

    scan_data_uuid = f"services_with_nuclei_templates-{uuid.uuid4()!s}"
    valkey_client.set(scan_data_uuid, json.dumps(result))
    return scan_data_uuid


async def run_nuclei_on_all_targets(valkey_client: Valkey, services_with_nuclei_templates_uuid: str) -> str:
    """
    Execute Nuclei scans on all targets and track CVE status results.

    :param valkey_client: Valkey client for retrieving service data
    :param services_with_nuclei_templates_uuid: UUID key for services with templates in Valkey
    :return: Coroutine that completes when all scans finish
    """
    cve_status: dict[str, str] = {}

    services_with_nuclei_templates = json.loads(str(valkey_client.get(services_with_nuclei_templates_uuid)))
    for service_data in services_with_nuclei_templates.values():
        service_template_data = dacite.from_dict(dtos.ServiceTemplateData, service_data)
        result = await run_nuclei_scan(service_template_data, cve_status)
        if result is not None:
            _determine_cve_status_from_nuclei_scan_results(result, service_template_data, cve_status)

    cve_status_uuid = f"cve_status-{uuid.uuid4()!s}"
    valkey_client.set(cve_status_uuid, json.dumps(cve_status))
    return cve_status_uuid


def _determine_cve_status_from_nuclei_scan_results(
    stdout: str, service_data: dtos.ServiceTemplateData, cve_status: dict[str, str]
) -> None:
    """
    Parse Nuclei scan output and determine CVE status (confirmed/unconfirmed).

    :param stdout: Nuclei scan output in JSON format (one JSON object per line)
    :param service_data: Service template data containing CVEs to check
    :param cve_status: Dictionary to update with CVE statuses (modified in place)
    :return: None
    """

    vulnerabilities_found = 0

    for cve_id in service_data.cves:
        if cve_id not in cve_status:
            cve_status[cve_id] = VulnerabilityStatus.UNCONFIRMED.value

    for line in stdout.strip().split("\n"):
        if not line:
            continue
        try:
            result = json.loads(line)

            if "info" in result and isinstance(result["info"], dict):
                classification = result["info"].get("classification", {})
                if "cve-id" in classification:
                    for cve_id in classification["cve-id"]:
                        if (cve_id := cve_id.upper()) in service_data.cves:
                            cve_status[cve_id] = VulnerabilityStatus.CONFIRMED.value
                            vulnerabilities_found += 1

        except json.JSONDecodeError:
            continue

    if vulnerabilities_found > 0:
        logger.info(
            f"Found {vulnerabilities_found} confirmed vulnerability/vulnerabilities at {service_data.target}:{service_data.port}"
        )


async def run_nuclei_scan(service_data: dtos.ServiceTemplateData, cve_status: dict[str, str]) -> str | None:
    """
    Execute Nuclei scan for a specific service using its CVE templates.

    :param service_data: ServiceTemplateData containing target, port, and templates
    :param cve_status: Dictionary to track CVE statuses (modified in place)
    :return: String containing Nuclei scan stdout output
    :raises NucleiRunError: If Nuclei scan fails with non-zero exit code
    """

    if not service_data.templates:
        # Mark CVEs as not_found if no templates exist
        for cve_id in service_data.cves:
            if cve_id not in cve_status:
                cve_status[cve_id] = VulnerabilityStatus.NOT_FOUND.value
        return None

    # Create target URL/endpoint
    scan_target = f"{service_data.target}:{service_data.port}"

    # Build nuclei command
    command = [
        NUCLEI_BINARY,
        "-u",
        scan_target,
        "-j",
        "-silent",
        "-rate-limit",
        "150",
        "-max-host-error",
        "30",
        "-t",
        ",".join(service_data.templates),  # Comma-separated list of templates
    ]

    # Run the scan
    stdout, stderr, returncode = await util.run_command_with_output(command)

    if stderr and returncode != 0:
        logger.warning(f"Nuclei scan on {scan_target} completed with errors: {stderr}")
        raise exceptions.NucleiRunError(stderr)

    return stdout


def _normalize_status(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if isinstance(value, str):
        return [value]
    return [str(value)]


def _compute_next_status(current_status: list[str], nuclei_status: str) -> list[str]:
    current_primary = current_status[0] if current_status else None
    current_secondary = next((status for status in current_status if status in {"assessed", "reassessed"}), None)

    if current_primary in {"resolved", "closed"}:
        next_primary = current_primary
    elif current_primary == VulnerabilityStatus.CONFIRMED.value and nuclei_status in {
        VulnerabilityStatus.UNCONFIRMED.value,
        VulnerabilityStatus.NOT_FOUND.value,
    }:
        next_primary = "closed"
    else:
        next_primary = nuclei_status

    if next_primary in {"closed", "resolved"}:
        return [next_primary]
    if current_secondary:
        return [next_primary, current_secondary]
    return [next_primary]


def _graphql_request(
    client: httpx.Client, graphql_url: str, query: str, variables: dict[str, object]
) -> dict[str, object]:
    resp = client.post(graphql_url, json={"query": query, "variables": variables})
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("errors"):
        logger.error("GraphQL request failed: %s", payload["errors"])
    return payload


def update_vulnerability_status(isim_urls: ISIMUrlsConfig, valkey_client: Valkey, cve_status_uuid: str) -> None:
    """
    Update vulnerability status in ISIM GraphQL API based on Nuclei scan results.

    :param isim_urls: Configuration for ISIM GraphQL endpoint
    :param valkey_client: Valkey client for retrieving CVE status data
    :param cve_status_uuid: UUID key for accessing CVE status dictionary in Valkey
    :return: None
    """
    cve_status = json.loads(str(valkey_client.get(cve_status_uuid)))
    logger.info("Updating vulnerabilities status in ISIM GraphQL: %s", cve_status)

    assets_dir = Path(__file__).parent / "assets"
    status_query = (assets_dir / "get_vulnerability_status.graphql").read_text(encoding="utf-8")
    status_mutation = (assets_dir / "update_vulnerability_status.graphql").read_text(encoding="utf-8")

    with httpx.Client(timeout=10) as client:
        for cve_id, nuclei_status in cve_status.items():
            query_payload = _graphql_request(
                client,
                isim_urls.graphql_url,
                status_query,
                {"cve_id": cve_id},
            )
            vulnerabilities = query_payload.get("data", {}).get("vulnerabilities", [])
            if not vulnerabilities:
                logger.warning("Skipping CVE %s because no vulnerability was found.", cve_id)
                continue

            current_status = _normalize_status(vulnerabilities[0].get("status"))
            next_status = _compute_next_status(current_status, str(nuclei_status))
            _graphql_request(
                client,
                isim_urls.graphql_url,
                status_mutation,
                {"cve_id": cve_id, "status": next_status},
            )

    logger.info("Updated vulnerabilities status in ISIM GraphQL: %s", cve_status)
