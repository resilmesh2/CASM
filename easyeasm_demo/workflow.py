import json
import subprocess
import uuid
from datetime import timedelta
from pathlib import Path

from neo4j import GraphDatabase, basic_auth
from redis.client import Redis
from temporalio import activity, workflow
from yaml import safe_dump

from easyeasm_demo.config import Neo4jConfig, RedisConfig, AppConfig

EASYEASM_BASE_PATH = "/tmp/easyeasm"


class EasyEasmActivities:
    def __init__(self, redis_config: RedisConfig, neo4j_config: Neo4jConfig):
        self.redis_config = redis_config
        self.neo4j_config = neo4j_config

    @activity.defn
    async def run_easyeasm(self, domains: list[str], mode: str = "fast") -> str:
        scan_id = uuid.uuid4().hex
        scan_dir = Path(EASYEASM_BASE_PATH) / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        with open(scan_dir / "config.yml", "w") as f:
            configuration = {
                "runConfig": {
                    "domains": domains,
                    "runType": mode,
                    "activeThreads": 10,
                    "activeWordList": "subdomains.txt"
                }
            }
            f.write(safe_dump(configuration))
        proc = subprocess.run("easyeasm", cwd=scan_dir, shell=True, capture_output=True)
        if proc.returncode != 0:
            return "FAIL"

        result_file = (Path(scan_dir) / "EasyEASM.csv")
        try:
            result = result_file.read_text("utf-8")
        except UnicodeDecodeError:
            print("Trying ISO 8859-2")
            result = result_file.read_text("iso-8859-2").encode("utf-8").decode()

        redis_client = Redis(host=self.redis_config.host, port=self.redis_config.port, db=0)
        redis_client.set(scan_id, result)
        redis_client.close()
        return scan_id

    @activity.defn
    async def store_result_to_neo4j(self, scan_id: str):
        query = """
        WITH apoc.convert.fromJsonMap($json_string) AS input_
        UNWIND input_.data as row
        CREATE (ipadd:EASM_IP { address: row.ip }) 
        CREATE (node:EASM_Node)-[:HAS_ASSIGNED]->(ipadd) 
        CREATE (host:EASM_Host)<-[:IS_A]-(node) 
        with host, row
        CREATE (domName: EASM_DomainName { domain_name: row.domain_name, tag: 'A/AAAA' })<-[:RESOLVES_TO]-(ipadd) 
        with host, row
        CREATE (networkService: EASY_NetworkService {service: row.service, tag: 'services_component', port: row.port, protocol: 'tcp'})-[:ON]->(host);
        """
        redis_client = Redis(host=self.redis_config.host, port=self.redis_config.port, db=0)
        neo4j_client = GraphDatabase.driver(
            self.neo4j_config.bolt,
            auth=basic_auth(self.neo4j_config.user,
            password=self.neo4j_config.password)
        )
        result = redis_client.get(scan_id).decode("utf-8").splitlines()
        loaded_result = {"data": []}
        for line in result[1:]:
            row = line.split(",")
            loaded_result["data"].append(
                {
                    "ip": row[7],
                    "domain_name": row[4],
                    "service": row[5],
                    "port": row[3]
                }
            )
        neo4j_client.execute_query(query, json_string=json.dumps(loaded_result))

    def get_activities(self):
        return [self.run_easyeasm, self.store_result_to_neo4j]


@workflow.defn(name="EasyEasmWorkflow")
class EasyEasmDemoWorkflow:
    @workflow.run
    async def run(self, domains: list[str], mode: str = "fast"):
        scan_uuid = await workflow.execute_activity(
            EasyEasmActivities.run_easyeasm,
            args=(domains, mode,),
            start_to_close_timeout=timedelta(hours=6)
        )
        await workflow.execute_activity(
            EasyEasmActivities.store_result_to_neo4j,
            args=(scan_uuid,),
            start_to_close_timeout=timedelta(hours=6)
        )

    @classmethod
    def get_activities(cls):
        config = AppConfig.get()
        activities = EasyEasmActivities(redis_config=config.redis, neo4j_config=config.neo4j)
        return [*activities.get_activities()]
