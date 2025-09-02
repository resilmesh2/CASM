from dataclasses import dataclass


@dataclass
class CveConnectorConfig:
    api_key: str | None = None
