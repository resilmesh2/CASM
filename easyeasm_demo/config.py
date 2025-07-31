from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dacite import from_dict

BASE_DIR = Path(__file__).resolve().parent.parent

TEMPORAL_URL = "localhost:7233"
TEMPORAL_NAMESPACE = "default"
TEMPORAL_TASK_QUEUE = "easyeasm_demo"


@dataclass
class Neo4jConfig:
    password: str = "supertestovaciheslo"
    bolt: str = "bolt://localhost:7687"
    user: str = "neo4j"


@dataclass
class TemporalConfig:
    url: str = TEMPORAL_URL
    namespace: str = TEMPORAL_NAMESPACE
    task_queue: str = TEMPORAL_TASK_QUEUE


@dataclass
class RedisConfig:
    host: str
    username: str | None = None
    password: str | None = None
    port: int = 6379


@dataclass
class NmapConfig:
    targets: list[str]
    arguments: str
    org_unit_name: str = "Internal IT"
    tag: list[str] = field(default_factory=list)

@dataclass
class ISIMConfig:
    url: str

@dataclass
class Config:
    temporal: TemporalConfig
    neo4j: Neo4jConfig
    redis: RedisConfig
    nmap: NmapConfig
    isim: ISIMConfig


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
