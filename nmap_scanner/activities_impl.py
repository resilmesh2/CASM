import ipaddress
from xml.etree import ElementTree

from dtos import Device, Host, NmapConfig, NmapResults, OrgUnit, SoftwareVersion, Subnet


def extract_subnet(ip_str: str, prefix: int = 24) -> str | None:
    #  TODO: ipv6
    try:
        ip = ipaddress.IPv4Address(ip_str)
        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return str(network)
    except Exception:
        return None


def parse_nmap_xml(config: NmapConfig) -> NmapResults:
    tree = ElementTree.parse(config.input_file)
    root = tree.getroot()
    results = NmapResults()

    subnet_set: set[str] = set()
    software_set: dict[str, set[str]] = {}

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        addr_elem = host.find("address")
        if addr_elem is None:
            continue

        ip = addr_elem.attrib.get("addr")
        subnet = extract_subnet(ip)
        if not subnet:
            continue

        # Add host entry
        results.hosts.append(Host(
            ip_address=ip,
            tag=config.tag,
            domain_names=[],
            uris=[],
            subnets=[subnet]
        ))

        # Add device entry
        results.devices.append(Device(
            name=ip,
            ip_address=ip,
            org_units=[config.org_unit_name]
        ))

        subnet_set.add(subnet)
        process_ports(host, ip, software_set)

    build_results(results, subnet_set, software_set, config)
    return results


def process_ports(host: ElementTree.Element, ip: str,
                        software_set: dict[str, set[str]]) -> None:
    ports = host.find("ports")
    if ports:
        for port in ports.findall("port"):
            service = port.find("service")
            if service is not None:
                full_version = build_version_string(service)
                if full_version:
                    if full_version not in software_set:
                        software_set[full_version] = set()
                    software_set[full_version].add(ip)


def build_version_string(service: ElementTree.Element) -> str | None:
    version = service.attrib.get("product", "")
    ver_detail = service.attrib.get("version", "")
    extrainfo = service.attrib.get("extrainfo", "")
    name = service.attrib.get("name", "")

    full_version = version
    if ver_detail:
        full_version += f" {ver_detail}"
    if extrainfo:
        full_version += f" ({extrainfo})"
    if not version:
        full_version = name

    full_version = full_version.strip()
    return full_version or None


def build_results(results: NmapResults, subnet_set: set[str],
                        software_set: dict[str, set[str]], config: NmapConfig) -> None:
    # Add subnets
    for subnet in sorted(subnet_set):
        results.subnets.append(Subnet(
            ip_range=subnet,
            note=f"Nmap scan results on {subnet}",
            org_units=[config.org_unit_name]
        ))

    # Add org unit
    results.org_units.append(OrgUnit(
        name=config.org_unit_name
    ))

    # Add software versions
    for version, ips in software_set.items():
        results.software_versions.append(SoftwareVersion(
            version=version,
            ip_addresses=sorted(ips),
            tag=config.tag
        ))
