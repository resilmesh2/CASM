import json
import subprocess  # noqa: S404
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase, basic_auth
from redis.client import Redis
from yaml import safe_dump

from easyeasm_demo.config import AppConfig, Neo4jConfig, RedisConfig
from temporalio import activity, workflow

EASYEASM_BASE_PATH = "/tmp/easyeasm"  # noqa: S108


class EasyEasmActivities:
    def __init__(self, redis_config: RedisConfig, neo4j_config: Neo4jConfig) -> None:
        self.redis_config = redis_config
        self.neo4j_config = neo4j_config

    @activity.defn
    async def run_easyeasm(self, scan_uuid: str, domains: list[str], mode: str = "fast") -> str:
        scan_dir = Path(EASYEASM_BASE_PATH) / scan_uuid
        scan_dir.mkdir(parents=True, exist_ok=True)
        configuration = {
            "runConfig": {
                "domains": domains,
                "runType": mode,
                "activeThreads": 10,
                "activeWordList": "subdomains.txt",
            }
        }
        Path(scan_dir / "config.yml", "w").write_text(safe_dump(configuration))
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
    async def store_result_to_neo4j(self, scan_uuid: str) -> None:
        query = """
        WITH apoc.convert.fromJsonMap($json_string) AS input_
        UNWIND input_.data AS row
        MERGE (ipadd:IP { address: row.ip })
        MERGE (node:Node)-[r1:HAS_ASSIGNED]->(ipadd)
        ON CREATE SET r1.start = datetime.truncate('second', datetime.fromepochmillis(TIMESTAMP()))
        MERGE (host:Host)<-[:IS_A]-(node)
        WITH host, row
        MERGE (domName: DomainName { domain_name: row.domain_name, tag: 'A/AAAA' })<-[r2:RESOLVES_TO]-(ipadd)
        ON CREATE SET r2.start = datetime.truncate('second', datetime.fromepochmillis(TIMESTAMP()))
        WITH host, row
        MERGE (networkService: NetworkService {service: row.service, tag: 'CASM', port: row.port, protocol: 'tcp'})-[r3:ON]->(host)
        ON CREATE SET r3.start = datetime.truncate('second', datetime.fromepochmillis(TIMESTAMP()));
        """
        redis_client = Redis(host=self.redis_config.host, port=self.redis_config.port, db=0)
        neo4j_client = GraphDatabase.driver(
            self.neo4j_config.bolt, auth=basic_auth(self.neo4j_config.user, password=self.neo4j_config.password)
        )
        result = redis_client.get(scan_uuid).decode("utf-8").splitlines()
        loaded_result = {"data": []}
        for line in result[1:]:
            row = line.split(",")
            loaded_result["data"].append({"ip": row[7], "domain_name": row[4], "service": row[5], "port": row[3]})
        neo4j_client.execute_query(query, json_string=json.dumps(loaded_result))

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_easyeasm, self.store_result_to_neo4j]


@workflow.defn(name="EasyEasmWorkflow")
class EasyEasmDemoWorkflow:
    @workflow.run
    async def run(self, scan_uuid: str, domains: list[str], mode: str = "fast") -> None:
        scan_uuid = await workflow.execute_activity(
            EasyEasmActivities.run_easyeasm,
            args=(
                scan_uuid,
                domains,
                mode,
            ),
            start_to_close_timeout=timedelta(hours=6),
        )
        await workflow.execute_activity(
            EasyEasmActivities.store_result_to_neo4j, args=(scan_uuid,), start_to_close_timeout=timedelta(hours=6)
        )

    @classmethod
    def get_activities(cls) -> Sequence[Callable[..., Awaitable[Any]]]:
        config = AppConfig.get()
        activities = EasyEasmActivities(redis_config=config.redis, neo4j_config=config.neo4j)
        return [*activities.get_activities()]
