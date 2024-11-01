from dataclasses import asdict, dataclass
from ipaddress import IPv4Interface, IPv6Interface
from socket import getaddrinfo
from typing import Any

from structlog import getLogger
from validators import ValidationError, domain

logger = getLogger()


def validate_input_target(target: str) -> bool:
    res = domain(target)
    if isinstance(res, ValidationError):
        return False
    return True


@dataclass
class EasyEASMParsedResult:
    port: int
    protocol: str
    service: str
    ip: IPv4Interface | IPv6Interface | None = None
    domain_name: str | None = None

    def __post_init__(self) -> None:
        if self.ip is None and self.domain_name is None:
            raise ValueError("Either IP or domain is necessary!")
        if self.ip and self.domain_name:
            info = getaddrinfo(self.domain_name, self.port)
            for res in info:
                if res[4][0] == self.ip:
                    return
            raise ValueError("IP does not correspond to a domain!")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
