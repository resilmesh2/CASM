import json
import subprocess  # noqa: S404
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase, basic_auth
from redis.client import Redis
from structlog import getLogger
from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from yaml import safe_dump

from config import AppConfig, Neo4jConfig, RedisConfig
from easyeasm_demo.queries import CASM_INSERT_QUERY
from easyeasm_demo.utils import EasyEASMParsedResult, determine_software_versions, validate_input_target

EASYEASM_BASE_PATH = "/tmp/easyeasm"  # noqa: S108

logger = getLogger()


@dataclass
class CASMInput:
    domains: list[str]
    scan_uuid: str = uuid.uuid4().hex
    mode: str = "fast"

    def to_dict(self) -> dict[str, Any]:
        return {"domains": self.domains, "scan_uuid": self.scan_uuid, "mode": self.mode}


class EasyEasmActivities:
    def __init__(self, redis_config: RedisConfig, neo4j_config: Neo4jConfig) -> None:
        self.redis_config = redis_config
        self.neo4j_config = neo4j_config

    @activity.defn
    async def validate_input(self, input_: dict[str, Any]) -> tuple[str, list[str], str]:
        obj_input = CASMInput(**input_)
        if obj_input.mode.lower() not in ["fast", "complete"]:
            raise ValueError("Invalid mode!")
        if not all(map(validate_input_target, obj_input.domains)):
            raise ValueError("Invalid targets!")
        return obj_input.scan_uuid, obj_input.domains, obj_input.mode.lower()

    @activity.defn
    async def run_easyeasm(self, scan_uuid: str, domains: list[str], mode: str = "fast") -> str:
        scan_dir = Path(EASYEASM_BASE_PATH) / scan_uuid
        scan_dir.mkdir(parents=True, exist_ok=True)
        configuration = {
            "runConfig": {
                "domains": domains,
                "runType": mode,
            }
        }
        Path(scan_dir / "config.yml").write_text(safe_dump(configuration))
        proc = subprocess.run("easyeasm", cwd=scan_dir, capture_output=True)
        if proc.returncode != 0:
            return "FAIL"

        result_file = Path(scan_dir) / "EasyEASM.csv"
        try:
            result = result_file.read_text("utf-8")
        except UnicodeDecodeError:
            result = result_file.read_text("iso-8859-2").encode("utf-8").decode()

        redis_client = Redis(host=self.redis_config.host, port=self.redis_config.port, db=0)
        redis_client.set(scan_uuid, result)
        redis_client.close()
        return scan_uuid

    @activity.defn
    async def store_result_to_neo4j(self, scan_uuid: str, domains: list[str]) -> None:
        redis_client = Redis(host=self.redis_config.host, port=self.redis_config.port, db=0)
        neo4j_client = GraphDatabase.driver(
            self.neo4j_config.bolt, auth=basic_auth(self.neo4j_config.user, password=self.neo4j_config.password)
        )
        result = redis_client.get(scan_uuid).decode("utf-8").splitlines()
        redis_client.close()
        loaded_result = {"data": []}

        domains_to_ips = {}
        subdomains_by_root_domains = {}
        for root in domains:
            subdomains_by_root_domains[root] = []

        for line in result[1:]:
            row = line.split(",")
            try:
                entry = EasyEASMParsedResult(
                    ip=row[7],
                    domain_name=row[4],
                    service=row[5],
                    port=row[3],
                    protocol=row[5],
                    software_versions=determine_software_versions(row[12]),
                )

                loaded_result["data"].append(entry.to_dict())

                if entry.domain_name not in domains_to_ips:
                    domains_to_ips[entry.domain_name] = []
                if entry.ip not in domains_to_ips[entry.domain_name]:
                    domains_to_ips[entry.domain_name].append(entry.ip)

                # add to correct root
                root_candidates = set()
                for root_candidate in domains:
                    if entry.domain_name.endswith(root_candidate):
                        root_candidates.add(root_candidate)
                root = str(max(root_candidates, key=len))

                if entry.domain_name not in subdomains_by_root_domains[root]:
                    subdomains_by_root_domains[root].append(entry.domain_name)

            except Exception:
                logger.exception("Invalid entry!")
        # we will first insert the data
        neo4j_client.execute_query(CASM_INSERT_QUERY, json_string=json.dumps(loaded_result))

        # now for consistency
        with neo4j_client.session() as session:
            # Get rid of not seen subdomains
            for root, domains in subdomains_by_root_domains.items():
                query = """
                    MATCH (d:DomainName) WHERE d.domain_name ENDS WITH $root_domain AND NOT d.domain_name IN $domains
                    MATCH (d)-[r:RESOLVES_TO]-(:IP)
                    SET r.end = datetime.truncate('second', datetime.fromepochmillis(TIMESTAMP()))
                    RETURN r
                """
                session.run(query, root_domain=root, domains=domains)
        with neo4j_client.session() as session:
            # Get rid of old IP addresses
            for domain, ips in domains_to_ips.items():
                query = """
                MATCH (d:DomainName {domain_name: $domain_name})
                MATCH (ip:IP) WHERE NOT ip.address in $ips
                MATCH (d)-[r:RESOLVES_TO]-(ip)
                SET r.end = datetime.truncate('second', datetime.fromepochmillis(TIMESTAMP()))
                RETURN r
                """
                session.run(query, domain_name=domain, ips=ips)
        neo4j_client.close()

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.validate_input, self.run_easyeasm, self.store_result_to_neo4j]


@workflow.defn(name="EasyEasmWorkflow")
class EasyEasmWorkflow:
    @workflow.run
    async def run(self, input_: dict[str, Any]) -> None:
        scan_uuid, domains, mode = await workflow.execute_activity(
            EasyEasmActivities.validate_input,
            arg=input_,
            retry_policy=RetryPolicy(
                maximum_attempts=1,
            ),
            start_to_close_timeout=timedelta(minutes=5),
        )

        scan_uuid = await workflow.execute_activity(
            EasyEasmActivities.run_easyeasm,
            args=(
                scan_uuid,
                domains,
                mode,
            ),
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError"],
            ),
            start_to_close_timeout=timedelta(hours=6),
        )
        await workflow.execute_activity(
            EasyEasmActivities.store_result_to_neo4j,
            args=(
                scan_uuid,
                domains,
            ),
            start_to_close_timeout=timedelta(hours=6),
            retry_policy=RetryPolicy(
                backoff_coefficient=2.0,
                maximum_attempts=5,
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=2),
                non_retryable_error_types=["ValueError"],
            ),
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = EasyEasmActivities(redis_config=config.redis, neo4j_config=config.neo4j)
        return [*activities.get_activities()]
