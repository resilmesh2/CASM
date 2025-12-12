from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dacite import from_dict

BASE_DIR = Path(__file__).resolve().parent

TEMPORAL_URL = "resilmesh_sap_wo_temporal:7233"
TEMPORAL_NAMESPACE = "default"
HTTPX_PATH_DOCKER = "/app/go/bin/httpx"


@dataclass
class Neo4jConfig:
    password: str = "supertestovaciheslo"
    bolt: str = "bolt://resilmesh_sap_neo4j:7687"
    user: str = "neo4j"


@dataclass
class TemporalConfig:
    url: str = TEMPORAL_URL
    namespace: str = TEMPORAL_NAMESPACE
    easm_task_queue: str = "easm"
    nmap_task_queue: str = "nmap"
    cve_connector_task_queue: str = "cve_connector"
    slp_enrichment_task_queue: str = "slp_enrichment"


@dataclass
class RedisConfig:
    host: str
    username: str | None = None
    password: str | None = None
    port: int = 6379


@dataclass
class NmapBasicConfig:
    targets: list[str]
    arguments: str
    org_unit_name: str = "Internal IT"
    tag: list[str] = field(default_factory=list)


@dataclass
class ISIMConfig:
    url: str


@dataclass
class NmapTopologyConfig:
    targets: list[str]
    arguments: str


@dataclass
class EasmScannerConfig:
    domains: list[str]
    mode: str
    httpx_path: str = HTTPX_PATH_DOCKER
    threads: int = 100
    wordlist_path: str | None = None
    complete: bool = False

    def __post_init__(self) -> None:
        if self.mode not in ("fast", "complete"):
            raise ValueError(f"invalid mode: {self.mode!r} (expected 'fast' or 'complete')")

        if self.mode == "complete":
            self.complete = True

        # wordlist requirement only for complete mode
        if self.complete:
            if not self.wordlist_path:
                raise ValueError("wordlist is required when mode == 'complete'")
            p = Path(self.wordlist_path)
            if not p.exists() or not p.is_file():
                raise ValueError(f"wordlist path does not exist or is not a file: {self.wordlist_path!r}")


@dataclass
class SLPEnrichmentConfig:
    x_api_key: str = ""


@dataclass
class CveConnectorConfig:
    nvd_api_key: str | None = None


@dataclass
class Config:
    temporal: TemporalConfig
    neo4j: Neo4jConfig
    redis: RedisConfig
    nmap_basic: NmapBasicConfig
    nmap_topology: NmapTopologyConfig
    isim: ISIMConfig
    easm_scanner: EasmScannerConfig
    slp_enrichment: SLPEnrichmentConfig
    cve_connector: CveConnectorConfig


class AppConfig:
    _config: Config | None = None

    @classmethod
    def get(cls) -> Config:
        if cls._config is None:
            config_file = BASE_DIR / "config/config.yaml"
            with Path.open(config_file, "r") as f:
                raw_config = yaml.safe_load(f)
            cls._config = from_dict(Config, raw_config)
        return cls._config
