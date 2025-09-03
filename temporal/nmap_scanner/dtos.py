from dataclasses import dataclass, field


@dataclass
class Host:
    ip_address: str
    tag: list[str]
    domain_names: list[str]
    uris: list[str]
    subnets: list[str]


@dataclass
class Subnet:
    ip_range: str
    note: str = field(default="")
    contacts: list[str] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)
    org_units: list[str] = field(default_factory=list)


@dataclass
class Device:
    name: str
    ip_address: str
    org_units: list[str] = field(default_factory=list)


@dataclass
class SoftwareVersion:
    version: str
    description: str
    ip_addresses: list[str]
    tag: list[str]


@dataclass
class Application:
    name: str
    device: str


@dataclass
class NmapResults:
    hosts: list[Host] = field(default_factory=list)
    subnets: list[Subnet] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    software_versions: list[SoftwareVersion] = field(default_factory=list)
    applications: list[Application] = field(default_factory=list)
