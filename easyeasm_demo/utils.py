import json
import urllib.request
from dataclasses import asdict, dataclass
from ipaddress import IPv4Interface, IPv6Interface
from typing import Any

from structlog import getLogger
from validators import ValidationError, domain

logger = getLogger()

WAPPALYZERGO_FINGERPRINTS_URL = (
    "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json"
)


def validate_input_target(target: str) -> bool:
    res = domain(target)
    return not isinstance(res, ValidationError)


def determine_software_versions(raw_technologies: str) -> list[dict[str, str]]:
    technologies = raw_technologies[1:-1].split(" ")
    with urllib.request.urlopen(WAPPALYZERGO_FINGERPRINTS_URL) as jsonfile:
        fingerprints_data = json.load(jsonfile)
        count_of_words = max(len(version.split(" ")) for version in fingerprints_data["apps"])

        i = 0
        j = 1
        software_versions = []

        while i < len(technologies):
            numerical_version = None
            technology = " ".join(technologies[i:j])

            if ":" in technologies[j - 1]:
                numerical_version = technology[technology.rfind(":") + 1 :]
                technology = technology[: technology.rfind(":")]

            if technology in fingerprints_data["apps"]:
                if "cpe" in fingerprints_data["apps"][technology]:
                    cpe_parts = fingerprints_data["apps"][technology]["cpe"].split(":")[3:6]
                    if numerical_version:
                        potential_version = {
                            "name": technology + ":" + numerical_version,
                            "version": ":".join([*cpe_parts[0:2], numerical_version]),
                        }
                    else:
                        potential_version = {"name": technology, "version": ":".join(cpe_parts)}
                else:
                    potential_version = (
                        {"name": technology + ":" + numerical_version} if numerical_version else {"name": technology}
                    )
                if potential_version not in software_versions:
                    software_versions.append(potential_version)

            if j <= i + count_of_words and j < len(technologies):
                j += 1
            else:
                i += 1
                j = i + 1

    return software_versions


@dataclass
class EasyEASMParsedResult:
    port: int
    protocol: str
    service: str
    ip: IPv4Interface | IPv6Interface | None = None
    domain_name: str | None = None
    software_versions: list[str] | None = None

    def __post_init__(self) -> None:
        if self.ip is None and self.domain_name is None:
            raise ValueError("Either IP or domain is necessary!")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
