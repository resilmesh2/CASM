from dataclasses import dataclass, field


@dataclass
class CVE:
    """Represents a CVE entry"""

    cve_id: str
    cpe_type: list[str] = field(default_factory=list)
    status: str = "unconfirmed"  # unconfirmed, confirmed, not_found


@dataclass
class Vulnerability:
    """Represents a vulnerability with CVE information"""

    cve: CVE


@dataclass
class SoftwareVersion:
    """Represents a software version with vulnerabilities"""

    vulnerabilities: list[Vulnerability] = field(default_factory=list)


@dataclass
class NetworkService:
    """Represents a network service"""

    protocol: str
    port: int
    service: str
    software_versions: list[SoftwareVersion] = field(default_factory=list)


@dataclass
class DomainName:
    """Represents a domain name"""
    domain_name: str

@dataclass
class IPAddress:
    """Represents an IP address with domain names"""

    address: str
    domain_names: list[DomainName] = field(default_factory=list)


@dataclass
class Node:
    """Represents a node with IP addresses"""

    ips: list[IPAddress] = field(default_factory=list)


@dataclass
class Host:
    """Represents a host with network services and node info"""

    network_services: list[NetworkService] = field(default_factory=list)
    node: Node | None = None


@dataclass
class NetworkServiceData:
    """Main scan data structure"""

    hosts: list[Host] = field(default_factory=list)


@dataclass
class ServiceTemplateData:
    """Represents service data with associated Nuclei templates"""

    target: str
    ip_address: str
    port: int
    service: str
    protocol: str
    cves: list[str] = field(default_factory=list)
    templates: list[str] = field(default_factory=list)
