#!/usr/bin/env python3
"""
Nuclei Template Scanner with subprocess
Parses JSON data, searches for Nuclei templates matching CVEs, and runs scans using nuclei binary.
"""

import json
import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path
from temporal.lib import util

# Template directory paths
NUCLEI_TEMPLATE_DIR = Path("/root/nuclei-templates")
HTTP_CVE_TEMPLATES_PATH = NUCLEI_TEMPLATE_DIR / "http" / "cves"
NETWORK_CVE_TEMPLATES_PATH = NUCLEI_TEMPLATE_DIR / "network" / "cves"
NUCLEI_BINARY = "nuclei"


@dataclass
class CVE:
    """Represents a CVE entry"""

    cve_id: str
    cpe_type: List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    """Represents a vulnerability with CVE information"""

    cve: CVE


@dataclass
class SoftwareVersion:
    """Represents a software version with vulnerabilities"""

    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class NetworkService:
    """Represents a network service"""

    protocol: str
    port: int
    service: str
    software_versions: List[SoftwareVersion] = field(default_factory=list)


@dataclass
class DomainName:
    """Represents a domain name"""

    domain_name: str


@dataclass
class IPAddress:
    """Represents an IP address with domain names"""

    address: str
    domain_names: List[DomainName] = field(default_factory=list)


@dataclass
class Node:
    """Represents a node with IP addresses"""

    ips: List[IPAddress] = field(default_factory=list)


@dataclass
class Host:
    """Represents a host with network services and node info"""

    network_services: List[NetworkService] = field(default_factory=list)
    node: Optional[Node] = None


@dataclass
class ScanData:
    """Main scan data structure"""

    hosts: List[Host] = field(default_factory=list)


async def update_nuclei(nucleiPath=None):
    """
    Checks and updates Nuclei.

    Checks for any updates to Nuclei or Nuclei Templates,
    and installs them if any.
    """

    processes = list()
    nucleiBinary = "nuclei"
    if nucleiPath:
        nucleiBinary = f"{nucleiPath}/{nucleiBinary}"

    commands = [
        [nucleiBinary, "-update-templates"],
        [nucleiBinary, "-update"]
    ]

    for command in commands:
        await util.run_command_with_output(command)

    for process in processes:
        output, error = process.communicate()
        if verbose:
            print(f"[Stdout] {output.decode('utf-8', 'ignore')}")
            print(f"[Stderr] {error.decode('utf-8', 'ignore')}")



def parse_json_to_dataclass(json_data) -> ScanData:
    """Parse JSON into ScanData dataclass"""
    if isinstance(json_data, str):
        data = json.loads(json_data)
    else:
        data = json_data

    # Navigate to the hosts array
    hosts_data = data.get("data", {}).get("hosts", [])

    hosts = []
    for host_data in hosts_data:
        # Parse network services
        services = []
        for svc in host_data.get("network_services", []):
            software_versions = []
            for sv in svc.get("software_versions", []):
                vulnerabilities = []
                for vuln in sv.get("vulnerabilities", []):
                    cve_data = vuln.get("cve", {})
                    cve = CVE(cve_id=cve_data.get("cve_id", ""), cpe_type=cve_data.get("cpe_type", []))
                    vulnerabilities.append(Vulnerability(cve=cve))

                software_versions.append(SoftwareVersion(vulnerabilities=vulnerabilities))

            services.append(
                NetworkService(
                    protocol=svc.get("protocol", ""),
                    port=svc.get("port", 0),
                    service=svc.get("service", ""),
                    software_versions=software_versions,
                )
            )

        # Parse node information
        node_data = host_data.get("node", {})
        ips = []
        for ip_data in node_data.get("ips", []):
            domain_names = [DomainName(domain_name=dn.get("domain_name", "")) for dn in ip_data.get("domain_names", [])]
            ips.append(IPAddress(address=ip_data.get("address", ""), domain_names=domain_names))

        node = Node(ips=ips) if ips else None

        hosts.append(Host(network_services=services, node=node))

    return ScanData(hosts=hosts)


def search_nuclei_templates(cve_id: str, service: str) -> List[str]:
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
    if service.lower() == "http":
        search_paths = [HTTP_CVE_TEMPLATES_PATH, NETWORK_CVE_TEMPLATES_PATH]
    else:
        search_paths = [NETWORK_CVE_TEMPLATES_PATH]

    # Extract year from CVE ID (e.g., CVE-2021-12345 -> 2021)
    try:
        cve_parts = cve_id.split("-")
        if len(cve_parts) >= 2:
            cve_year = cve_parts[1]
        else:
            cve_year = None
    except:
        cve_year = None

    for search_path in search_paths:
        if not search_path.exists():
            print(f"Warning: Template path does not exist: {search_path}")
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


def extract_all_cves(host: Host) -> List[str]:
    """Extract all unique CVE IDs from a host"""
    cves = set()
    for service in host.network_services:
        for sw_version in service.software_versions:
            for vuln in sw_version.vulnerabilities:
                if vuln.cve.cve_id:
                    cves.add(vuln.cve.cve_id)
    return sorted(list(cves))


def build_template_dict(scan_data: ScanData) -> Dict[str, Dict]:
    """
    Build dictionary mapping services to found Nuclei templates

    Returns:
        Dictionary with host+service keys and found templates
    """
    result = {}

    for host_idx, host in enumerate(scan_data.hosts):
        # Get primary domain name or IP
        target = "unknown"
        ip_address = "unknown"

        if host.node and host.node.ips:
            ip_obj = host.node.ips[0]
            ip_address = ip_obj.address
            if ip_obj.domain_names:
                target = ip_obj.domain_names[0].domain_name
            else:
                target = ip_address

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
                            print(f"Found {len(templates)} template(s) for {cve_id} on {service_key}")

            # Remove duplicates while preserving Path objects
            all_templates = list(set(all_templates))
            all_cves = list(set(all_cves))

            result[service_key] = {
                "target": target,
                "ip_address": ip_address,
                "port": service.port,
                "service": service.service,
                "protocol": service.protocol,
                "cves": all_cves,
                "templates": all_templates,
            }

    return result


async def run_nuclei_scan(service_key: str, service_data: Dict, confirmed_cves: Dict[str, bool]) -> Dict:
    """
    Run Nuclei scan for a specific service using subprocess

    Args:
        service_key: Service identifier
        service_data: Service data including templates
        confirmed_cves: Dictionary to track confirmed CVEs

    Returns:
        Dictionary with scan status
    """
    target = service_data["target"]
    port = service_data["port"]
    templates = service_data["templates"]
    cves = service_data["cves"]

    if not templates:
        print(f"⚠️  No templates found for {service_key}")
        return {"status": "skipped", "reason": "no_templates"}

    # Create target URL/endpoint
    scan_target = f"{target}:{port}"

    print(f"\n{'=' * 80}")
    print(f"🎯 Scanning: {service_key}")
    print(f"   Target: {scan_target}")
    print(f"   CVEs: {', '.join(cves)}")
    print(f"   Templates: {len(templates)}")
    print(f"{'=' * 80}")

    try:
        # Build nuclei command
        command = [
            NUCLEI_BINARY,
            "-u",
            scan_target,
            "-json",
            "-silent",
            "-rate-limit",
            "150",
            "-max-host-error",
            "30",
            "-t",
            ",".join(templates),  # Comma-separated list of templates
        ]

        # Run the scan
        print(f"🔍 Running command {command}")
        stdout, stderr, returncode = await util.run_command_with_output(command)

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
                        if isinstance(classification, dict) and "cve-id" in classification:
                            cve_id_list = classification["cve-id"]
                            if isinstance(cve_id_list, list) and cve_id_list:
                                cve_found = cve_id_list[0]
                            elif isinstance(cve_id_list, str):
                                cve_found = cve_id_list

                    # Mark CVE as confirmed
                    if cve_found and cve_found in cves:
                        confirmed_cves[cve_found] = True
                        vulnerabilities_found += 1

                except json.JSONDecodeError:
                    continue

        if vulnerabilities_found > 0:
            print(f"✅ Scan completed: {vulnerabilities_found} CVE(s) confirmed")
        else:
            print(f"✅ Scan completed: No vulnerabilities confirmed")

        if stderr and returncode != 0:
            print(f"⚠️  Stderr: {stderr}")

        return {"status": "completed", "target": scan_target, "vulnerabilities_found": vulnerabilities_found}

    except Exception as e:
        print(f"❌ Error during scan: {str(e)}")
        return {"status": "error", "target": scan_target, "error": str(e)}


async def main():
    """Main execution function"""

    print("=" * 80)
    print("NUCLEI VULNERABILITY SCANNER")
    print("=" * 80)

    await update_nuclei()
    # Load JSON data from file
    json_file = Path(__file__).parent / "cves.json"

    if not json_file.exists():
        print(f"❌ Error: JSON file not found at {json_file}")
        return

    print(f"\n📋 Loading JSON data from {json_file}...")
    with open(json_file, "r") as f:
        json_data = json.load(f)

    # Parse JSON to dataclass
    print("📋 Parsing JSON data...")
    scan_data = parse_json_to_dataclass(json_data)
    print(f"✓ Hosts found: {len(scan_data.hosts)}")

    # Display host summary
    print("\n📊 Host Summary:")
    for idx, host in enumerate(scan_data.hosts):
        if host.node and host.node.ips:
            ip = host.node.ips[0]
            domain = ip.domain_names[0].domain_name if ip.domain_names else "N/A"
            print(f"\nHost {idx + 1}: {domain}")
            print(f"  IP: {ip.address}")
            print(f"  Services: {len(host.network_services)}")
            print(f"  CVEs: {len(extract_all_cves(host))}")

    # Build template dictionary
    print("\n\n🔍 Searching for Nuclei templates...")
    template_dict = build_template_dict(scan_data)

    # Run scans
    print("\n\n🚀 Starting Nuclei Scans...")

    # Dictionary to track confirmed CVEs
    confirmed_cves = {}
    scan_results = {}

    for service_key, service_data in template_dict.items():
        result = await run_nuclei_scan(service_key, service_data, confirmed_cves)
        scan_results[service_key] = result

    # Summary
    print("\n\n" + "=" * 80)
    print("📈 SCAN SUMMARY")
    print("=" * 80)

    total_services = len(template_dict)
    services_with_templates = sum(1 for s in template_dict.values() if s["templates"])
    total_cves = sum(len(s["cves"]) for s in template_dict.values())
    completed_scans = sum(1 for r in scan_results.values() if r["status"] == "completed")
    total_confirmed = len(confirmed_cves)

    print(f"\nTotal services scanned: {total_services}")
    print(f"Services with templates: {services_with_templates}")
    print(f"Total CVEs checked: {total_cves}")
    print(f"Completed scans: {completed_scans}")
    print(f"Confirmed vulnerabilities: {total_confirmed}")

    if confirmed_cves:
        print(f"\n🔴 Confirmed CVEs:")
        for cve_id in sorted(confirmed_cves.keys()):
            print(f"   - {cve_id}")


if __name__ == "__main__":
    asyncio.run(main())
