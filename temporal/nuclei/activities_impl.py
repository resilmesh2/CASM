#!/usr/bin/env python3
"""
Nuclei Template Scanner with subprocess
Parses JSON data, searches for Nuclei templates matching CVEs, and runs scans using nuclei binary.
"""

import asyncio
import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any, LiteralString

import dacite
from neo4j import GraphDatabase, basic_auth

from config import Neo4jConfig
from temporal.lib import util
from temporal.nuclei import dtos

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


async def update_nuclei(nuclei_path=None) -> dict:
    """
    Checks and updates Nuclei.

    Checks for any updates to Nuclei or Nuclei Templates,
    and installs them if any.

    Returns:
        Dictionary with status and any error messages
    """

    nuclei_binary = "nuclei"
    if nuclei_path:
        nuclei_binary = f"{nuclei_path}/{nuclei_binary}"

    commands = [[nuclei_binary, "-update-templates"], [nuclei_binary, "-update"]]

    results = []
    for command in commands:
        try:
            _stdout, _stderr, returncode = await util.run_command_with_output(command)
            logger.info(f"Executed {' '.join(command)}: returncode={returncode}")
            results.append({
                "command": " ".join(command),
                "returncode": returncode,
                "success": returncode == 0
            })
        except Exception as e:
            logger.exception(f"Failed to execute {' '.join(command)}: {e}")
            results.append({
                "command": " ".join(command),
                "success": False,
                "error": str(e)
            })

    return {"status": "completed", "updates": results}


def search_nuclei_templates(cve_id: str, service: str) -> list[str]:
    """
    Search for Nuclei templates matching a CVE

    Args:
        cve_id: CVE identifier (e.g., CVE-2021-12345)
        service: Service name (e.g., 'http', 'ssh', 'ftp')

    Returns:
        List of matching template file paths as strings
    """
    matching_templates = []

    # Determine which template paths to search
    search_paths = (
        [HTTP_CVE_TEMPLATES_PATH, NETWORK_CVE_TEMPLATES_PATH]
        if service.lower() == "http"
        else [NETWORK_CVE_TEMPLATES_PATH]
    )

    # Extract year from CVE ID (e.g., CVE-2021-12345 -> 2021)
    try:
        cve_parts = cve_id.split("-")
        cve_year = cve_parts[1] if len(cve_parts) >= 2 else None
    except:
        cve_year = None

    for search_path in search_paths:
        if not search_path.exists():
            continue

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


def build_template_dict(scan_data: dtos.ScanData) -> dict[str, dtos.ServiceTemplateData]:
    """
    Build dictionary mapping services to found Nuclei templates

    Returns:
        Dictionary with host+service keys and ServiceTemplateData objects
    """
    result = {}

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
            all_templates = []
            all_cves = []

            # Collect all CVEs for this service
            for sw_version in service.software_versions:
                for vuln in sw_version.vulnerabilities:
                    cve_id = vuln.cve.cve_id
                    if cve_id:
                        all_cves.append(cve_id)
                        templates = search_nuclei_templates(cve_id, service.service)
                        all_templates.extend(templates)

                        if templates:
                            logger.info(f"Found {len(templates)} template(s) for {cve_id}")

            # Remove duplicates
            all_templates = list(set(all_templates))
            all_cves = list(set(all_cves))

            result[service_key] = dtos.ServiceTemplateData(
                target=target,
                ip_address=ip_address,
                port=service.port,
                service=service.service,
                protocol=service.protocol,
                cves=all_cves,
                templates=all_templates,
            )

    return result


async def run_nuclei_scan(service_data: dtos.ServiceTemplateData, cve_status: dict[str, str]) -> dict:
    """
    Run Nuclei scan for a specific service using subprocess

    Args:
        service_data: ServiceTemplateData with templates and CVE information
        cve_status: Dictionary to track CVE status (unconfirmed, confirmed, not_found)

    Returns:
        Dictionary with scan status
    """
    target = service_data.target
    port = service_data.port
    templates = service_data.templates
    cves = service_data.cves

    if not templates:
        # Mark CVEs as not_found if no templates exist
        for cve_id in cves:
            if cve_id not in cve_status:
                cve_status[cve_id] = "not_found"
        return {"status": "skipped", "reason": "no_templates"}

    # Create target URL/endpoint
    scan_target = f"{target}:{port}"

    try:
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
            ",".join(templates),  # Comma-separated list of templates
        ]

        # Run the scan
        stdout, stderr, returncode = await util.run_command_with_output(command)

        # Initialize all CVEs as unconfirmed before scanning
        for cve_id in cves:
            if cve_id not in cve_status:
                cve_status[cve_id] = VulnerabilityStatus.UNCONFIRMED.value

        # Parse JSON results from stdout
        vulnerabilities_found = 0
        if stdout:
            for line in stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    result = json.loads(line)

                    # Extract CVE ID from result
                    cve_found = None

                    # Check template-id field
                    if "template-id" in result:
                        template_id = result["template-id"]
                        if template_id.startswith("CVE-"):
                            cve_found = template_id

                    # Check info.classification.cve-id field
                    if "info" in result and isinstance(result["info"], dict):
                        classification = result["info"].get("classification", {})
                        if "cve-id" in classification:
                            for cve_id in classification["cve-id"]:
                                if cve_id.upper().strip() in cves:
                                    cve_status[cve_id] = VulnerabilityStatus.CONFIRMED.value
                                    vulnerabilities_found += 1

                except json.JSONDecodeError:
                    continue

        if vulnerabilities_found > 0:
            logger.info(f"Found {vulnerabilities_found} confirmed vulnerability/vulnerabilities at {scan_target}")

        if stderr and returncode != 0:
            logger.warning(f"Nuclei scan on {scan_target} completed with errors: {stderr}")

        return {"status": "completed", "target": scan_target, "vulnerabilities_found": vulnerabilities_found}

    except Exception as e:
        return {"status": "error", "target": scan_target, "error": str(e)}


async def get_network_services_cves():
    # TODO: There will be graphql query later
    json_file = Path(__file__).parent / "cves.json"

    if not json_file.exists():
        logger.error(f"JSON file not found: {json_file}")
        return {"status": "error", "message": "cves.json not found"}

    with Path(json_file).open() as f:
        json_data = json.load(f)

    return json_data["data"]


def update_vulnerability_status(neo4j_config: Neo4jConfig, cve_status: dict[str, str]) -> None:
    neo4j_client = GraphDatabase.driver(
        neo4j_config.bolt, auth=basic_auth(neo4j_config.user, password=neo4j_config.password)
    )

    vulnerability_update: LiteralString = (Path(__file__).resolve().parent / "assets/update_vulnerabilities.cypher").read_text()
    neo4j_client.execute_query(vulnerability_update, cve_status=cve_status)


async def main() -> dict:
    """Main execution function

    Returns:
        Dictionary containing scan results summary
    """

    # Parse JSON to dataclass
    data_for_nuclei_scan = dacite.from_dict(dtos.ScanData, await get_network_services_cves())

    # Display host summary
    for idx, host in enumerate(data_for_nuclei_scan.hosts):
        if host.node and host.node.ips:
            ip = host.node.ips[0]
            domain = ip.domain_names[0].domain_name if ip.domain_names else "N/A"
            logger.info(f"Host {idx}: {ip.address} ({domain})")

    # Build template dictionary
    template_dict = build_template_dict(data_for_nuclei_scan)

    # Run scans

    # Dictionary to track CVE status
    cve_status = {}
    scan_results = {}

    for service_key, service_data in template_dict.items():
        result = await run_nuclei_scan(service_data, cve_status)
        scan_results[service_key] = result

    # Summary
    total_services = len(template_dict)
    total_cves = sum(len(s.cves) for s in template_dict.values())
    completed_scans = sum(1 for r in scan_results.values() if r["status"] == "completed")
    confirmed_cves = [cve_id for cve_id, status in cve_status.items() if status == "confirmed"]
    unconfirmed_cves = [cve_id for cve_id, status in cve_status.items() if status == "unconfirmed"]
    not_found_cves = [cve_id for cve_id, status in cve_status.items() if status == "not_found"]

    logger.info(f"Total CVEs: {total_cves}, Completed scans: {completed_scans}")
    logger.info(f"Confirmed: {len(confirmed_cves)}, Unconfirmed: {len(unconfirmed_cves)}, Not found: {len(not_found_cves)}")

    if confirmed_cves:
        for cve_id in sorted(confirmed_cves):
            logger.info(f"Confirmed CVE: {cve_id}")

    update_vulnerability_status(Neo4jConfig(), cve_status)

    return {
        "status": "completed",
        "total_services": total_services,
        "total_cves": total_cves,
        "completed_scans": completed_scans,
        "cve_status": cve_status,
        "confirmed_cves": confirmed_cves,
        "unconfirmed_cves": unconfirmed_cves,
        "not_found_cves": not_found_cves,
        "scan_results": scan_results
    }


if __name__ == "__main__":
    asyncio.run(main())
