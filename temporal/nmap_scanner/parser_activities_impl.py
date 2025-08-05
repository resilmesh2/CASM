import ipaddress
from xml.etree.ElementTree import Element

from temporal.nmap_scanner.dtos import Application, Device, Host, NmapResults, SoftwareVersion, Subnet


def _get_ip_version(ip: str) -> int:
    return ipaddress.ip_address(ip).version


def _get_default_prefix(ip_version: int) -> int:
    return 24 if ip_version == 4 else 64


def extract_subnet(ip_str: str, prefix: int | None = None) -> str | None:
    try:
        ip = ipaddress.ip_address(ip_str)
        prefix = prefix or _get_default_prefix(ip.version)
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(network)
    except Exception:
        return None


def _extract_ip_addresses(host: Element) -> list[str]:
    return [
        addr for address in host.findall("address")
        if (addr := address.attrib.get("addr", ""))
    ]


def _extract_hostnames(host: Element) -> list[str]:
    hostnames = []
    if (hostnames_elem := host.find("hostnames")) is not None:
        hostnames.extend(
            name for hostname in hostnames_elem.findall("hostname")
            if (name := hostname.attrib.get("name"))
        )
    return hostnames


def _build_version_description(service: Element) -> str:
    product = service.attrib.get("product", "")
    version = service.attrib.get("version", "")
    extrainfo = service.attrib.get("extrainfo", "")
    name = service.attrib.get("name", "")

    version_parts = [part for part in [product, version] if part]
    full_version = " ".join(version_parts)

    if extrainfo:
        full_version += f" ({extrainfo})"
    return full_version.strip() or name


def _get_service_cpe(service: Element) -> str:
    cpe_elem = service.find("cpe")
    return cpe_elem.text if cpe_elem is not None else service.attrib.get("cpe", "")


def convert_cpe_to_version_2_3(cpe: str) -> str | None:
    """
    Convert 'cpe:/a:vendor:product:version' to
    'cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*'
    Returns None if a version is missing.
    """
    parts = cpe.split(":")[1:]  # remove 'cpe:/'
    part = parts[0][1:] if parts[0].startswith("/") else parts[0]
    fields = [part] + parts[1:]
    if len(fields) < 4 or not fields[3].strip():  # Cve_connector doesn't support cpes without a version for now
        return None
    fields = fields[:4] + ["*"] * 6
    return "cpe:2.3:" + ":".join(fields)


def _create_software_version(service: Element, ip: str, tag: list[str]) -> SoftwareVersion | None:
    cpe = _get_service_cpe(service)
    if not (cpe and (cpe := convert_cpe_to_version_2_3(cpe))):
        return None

    return SoftwareVersion(
        version=cpe,
        description=_build_version_description(service),
        ip_addresses=[ip],
        tag=tag
    )


def _create_application(service: Element, port_num: str, protocol: str, ip: str) -> Application:
    service_name = service.attrib.get("name", "")
    app_name = f"{service_name} (port {port_num}/{protocol})"
    return Application(name=app_name, device=ip)


def _process_ports_and_services(host: Element, ip: str, software_versions: list[SoftwareVersion],
                              applications: list[Application], tag: list[str]) -> None:
    if (ports := host.find("ports")) is None:
        return

    for port in ports.findall("port"):
        port_num = port.attrib.get("portid", "")
        protocol = port.attrib.get("protocol", "tcp")

        state = port.find("state")
        service = port.find("service")
        if state is not None and state.attrib.get("state") == "open" and service is not None:
            if software_version := _create_software_version(service, ip, tag):
                software_versions.append(software_version)
            if service.attrib.get("name"):
                applications.append(_create_application(service, port_num, protocol, ip))


def _create_host(primary_ip: str, hostnames: list[str], host_subnets: list[str], tag: list[str]) -> Host:
    return Host(
        ip_address=primary_ip,
        tag=tag,
        domain_names=hostnames,
        uris=[],
        subnets=host_subnets
    )


def _create_device(ip: str, hostnames: list[str]) -> Device:
    device_name = hostnames[0] if hostnames else ip
    return Device(
        name=device_name,
        ip_address=ip,
    )


def _is_host_up(host: Element) -> bool:
    status = host.find("status")
    return status is not None and status.attrib.get("state") == "up"


def _extract_host_subnets(ip_addresses: list[str], subnet_set: set[str]) -> list[str]:
    host_subnets = []
    for ip in ip_addresses:
        if subnet := extract_subnet(ip):
            subnet_set.add(subnet)
            host_subnets.append(subnet)
    return host_subnets


def _add_devices(results: NmapResults, ip_addresses: list[str], hostnames: list[str]) -> None:
    for ip in ip_addresses:
        device = _create_device(ip, hostnames)
        if len(ip_addresses) > 1:
            device.name = f"{device.name} ({ip})"
        results.devices.append(device)


def _finalize_results(results: NmapResults, subnet_set: set[str], software_versions: list[SoftwareVersion],
                     applications: list[Application]) -> None:
    results.subnets.extend(
        Subnet(ip_range=subnet, note=subnet)
        for subnet in sorted(subnet_set)
    )
    results.software_versions.extend(software_versions)
    results.applications.extend(applications)


def parse_nmap_xml(nmap_output: Element, tag: list[str]) -> NmapResults:
    results = NmapResults()
    subnet_set: set[str] = set()
    software_versions: list[SoftwareVersion] = []
    applications: list[Application] = []

    for host in nmap_output.findall("host"):
        if not _is_host_up(host):
            continue

        ip_addresses = _extract_ip_addresses(host)
        if not ip_addresses:
            continue

        host_subnets = _extract_host_subnets(ip_addresses, subnet_set)
        hostnames = _extract_hostnames(host)
        primary_ip = ip_addresses[0]
        results.hosts.append(_create_host(primary_ip, hostnames, host_subnets, tag))

        _add_devices(results, ip_addresses, hostnames)
        for ip in ip_addresses:
            _process_ports_and_services(host, ip, software_versions, applications, tag)

    _finalize_results(results, subnet_set, software_versions, applications)
    return results
