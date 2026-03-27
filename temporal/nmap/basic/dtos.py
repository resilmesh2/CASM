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
    contacts: list[str] = field(default_factory=list[str])
    parents: list[str] = field(default_factory=list[str])
    org_units: list[str] = field(default_factory=list[str])


@dataclass
class Device:
    name: str
    ip_address: str
    org_units: list[str] = field(default_factory=list[str])


@dataclass
class SoftwareVersion:
    version: str
    description: str
    ip_addresses: list[str]
    tag: list[str] = field(default_factory=list[str])
    service: str | None = None
    protocol: str | None = None
    port: int | None = None


@dataclass
class Application:
    name: str
    device: str


@dataclass
class NmapResults:
    hosts: list[Host] = field(default_factory=list[Host])
    subnets: list[Subnet] = field(default_factory=list[Subnet])
    devices: list[Device] = field(default_factory=list[Device])
    software_versions: list[SoftwareVersion] = field(default_factory=list[SoftwareVersion])
    applications: list[Application] = field(default_factory=list[Application])
