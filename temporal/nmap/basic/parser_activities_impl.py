import ipaddress
from xml.etree.ElementTree import Element

from temporal.nmap.basic.dtos import Application, Device, Host, NmapResults, SoftwareVersion, Subnet


def _get_ip_version(ip: str) -> int:
    return ipaddress.ip_address(ip).version


def _get_default_prefix(ip_version: int) -> int:
    return 24 if ip_version == 4 else 64


def extract_subnet(ip_str: str, prefix: int | None = None) -> str | None:
    """
    Compute the CIDR subnet string for a given IP and optional prefix length.

    If no prefix is provided, a default of /24 for IPv4 and /64 for IPv6 is used.

    :param ip_str: IP address as a string.
    :param prefix: Optional prefix length to use for the network calculation.
    :return: CIDR notation string (e.g., "192.168.1.0/24") or None if ip_str is invalid.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        prefix = prefix or _get_default_prefix(ip.version)
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(network)
    except ValueError:
        return None


def _extract_ip_addresses(host: Element) -> list[str]:
    """
    Extract IPv4/IPv6 addresses from an nmap <host> element.

    :param host: XML element representing a host in nmap output.
    :return: List of address strings with addrtype ipv4/ipv6, in the order found.
    """
    return [
        addr
        for address in host.findall("address")
        if (addr := address.attrib.get("addr", "")) and address.attrib.get("addrtype") in ("ipv4", "ipv6")
    ]


def _extract_hostnames(host: Element) -> list[str]:
    """
    Collect hostname labels from an nmap <host> element.

    :param host: XML element for a host containing optional <hostnames>/<hostname> children.
    :return: List of hostname strings, empty if none are present.
    """
    hostnames = []
    if (hostnames_elem := host.find("hostnames")) is not None:
        hostnames.extend(
            name for hostname in hostnames_elem.findall("hostname") if (name := hostname.attrib.get("name"))
        )
    return hostnames


def _build_version_description(service: Element) -> str:
    """
    Build a human-friendly service description from nmap <service> attributes.

    Uses the "product", "version", and optional "extrainfo" attributes when available;
    falls back to the service "name" if product/version are absent.

    :param service: XML <service> element from a port result.
    :return: Description string like "nginx 1.24 (Ubuntu)" or the service name if unknown.
    """
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
    Convert a legacy CPE string ("cpe:/...") to the CPE 2.3 format.

    If the input CPE does not include a version component, None is returned because
    downstream consumers currently require a version.

    :param cpe: CPE string as reported by nmap (often in the "cpe:/a:vendor:product:version" form).
    :return: A CPE 2.3 string (e.g., "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*") or None.
    """
    parts = cpe.split(":")[1:]  # remove 'cpe:/'
    part = parts[0].removeprefix("/")
    fields = [part, *parts[1:]]
    if len(fields) < 4 or not fields[3].strip():  # Cve_connector doesn't support cpes without a version for now
        return None
    fields = fields[:4] + ["*"] * 6
    return "cpe:2.3:" + ":".join(fields)


def _create_software_version(service: Element, ip: str, tag: list[str]) -> SoftwareVersion | None:
    """
    Create a SoftwareVersion entry from a <service> element if a valid CPE exists.

    Converts legacy CPEs to 2.3 format and builds a descriptive string. If the
    service lacks a usable CPE with a version component, returns None.

    :param service: XML <service> element for an open port.
    :param ip: IP address of the host where the service was detected.
    :param tag: Tags to attach to the SoftwareVersion.
    :return: SoftwareVersion instance or None when no usable CPE is found.
    """
    cpe = _get_service_cpe(service)
    if not (cpe and (cpe := convert_cpe_to_version_2_3(cpe))):
        return None

    return SoftwareVersion(version=cpe, description=_build_version_description(service), ip_addresses=[ip], tag=tag)


def _create_application(service: Element, port_num: str, protocol: str, ip: str) -> Application:
    """
    Create a minimal Application record from a detected service/port.

    :param service: XML <service> element containing the service "name".
    :param port_num: Port number as a string from nmap attributes (e.g., "80").
    :param protocol: Transport protocol name (e.g., "tcp", "udp").
    :param ip: IP address of the device that hosts the application.
    :return: Application dataclass instance referencing the device by IP.
    """
    service_name = service.attrib.get("name", "")
    app_name = f"{service_name} (port {port_num}/{protocol})"
    return Application(name=app_name, device=ip)


def _process_ports_and_services(
    host: Element, ip: str, software_versions: list[SoftwareVersion], applications: list[Application], tag: list[str]
) -> None:
    """
    Inspect a host's <ports> and collect applications and software versions for open services.

    Only ports with state="open" and with a <service> element are considered. If the service
    has a usable CPE it is converted and added as a SoftwareVersion; if it has a name, an
    Application entry is created.

    :param host: XML <host> element to process.
    :param ip: IP address of the host being processed.
    :param software_versions: Accumulator list to extend with SoftwareVersion items.
    :param applications: Accumulator list to extend with Application items.
    :param tag: Tags to attach to SoftwareVersion entries.
    :return: None
    """
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
    return Host(ip_address=primary_ip, tag=tag, domain_names=hostnames, uris=[], subnets=host_subnets)


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
    """
    Compute and collect subnets for the given IPs, updating a global set.

    :param ip_addresses: List of host IP address strings.
    :param subnet_set: Set an accumulator of unique CIDR subnets across all hosts.
    :return: List of CIDR subnet strings associated with the given host IPs.
    """
    host_subnets = []
    for ip in ip_addresses:
        if subnet := extract_subnet(ip):
            subnet_set.add(subnet)
            host_subnets.append(subnet)
    return host_subnets


def _add_devices(results: NmapResults, ip_addresses: list[str], hostnames: list[str]) -> None:
    """
    Append Device records to results for each IP address on the host.

    If multiple IPs are associated with the same host, annotate the device name with
    the specific IP to keep them distinct.

    :param results: NmapResults accumulator to which devices are added.
    :param ip_addresses: All IPs found for the host.
    :param hostnames: Hostname list used to derive a base device name.
    :return: None
    """
    for ip in ip_addresses:
        device = _create_device(ip, hostnames)
        if len(ip_addresses) > 1:
            device.name = f"{device.name} ({ip})"
        results.devices.append(device)


def _finalize_results(
    results: NmapResults,
    subnet_set: set[str],
    software_versions: list[SoftwareVersion],
    applications: list[Application],
) -> None:
    """
    Transfer accumulated subnets, software versions, and applications into results.

    Subnets are sorted and converted into Subnet DTOs. Software versions and
    applications are appended as-is.

    :param results: Target NmapResults an object to populate.
    :param subnet_set: Unique set of CIDR subnet strings discovered during parsing.
    :param software_versions: Collected SoftwareVersion items.
    :param applications: Collected Application items.
    :return: None
    """
    results.subnets.extend(Subnet(ip_range=subnet, note=subnet) for subnet in sorted(subnet_set))
    results.software_versions.extend(software_versions)
    results.applications.extend(applications)


def parse_nmap_xml(nmap_output: Element, tag: list[str]) -> NmapResults:
    """
    Parse an nmap XML Element into the NmapResults data model.

    This processes hosts, devices, open ports, detected services, and CPEs into
    structured objects consumable by the ISIM API.

    :param nmap_output: The root Element of a nmap XML document.
    :param tag: List of tags to attach to produced SoftwareVersion records.
    :return: Populated NmapResults object with subnets, hosts, devices, apps, and versions.
    """
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
