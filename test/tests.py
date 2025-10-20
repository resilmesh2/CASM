import unittest
import uuid
from pathlib import Path

from neo4j import GraphDatabase, basic_auth
from redis.client import Redis

from config import AppConfig, Neo4jConfig, RedisConfig
from easyeasm_demo.workflow import EasyEasmActivities


class TestMethods(unittest.IsolatedAsyncioTestCase):
    async def test_storing_to_neo4j(self) -> None:
        # Store results from scanning to Redis
        scan_uuid = str(uuid.uuid4())
        result_file = Path("test-data/scan.csv")
        try:
            result = result_file.read_text("utf-8")
        except UnicodeDecodeError:
            result = result_file.read_text("iso-8859-2").encode("utf-8").decode()

        config = AppConfig.get()
        redis_client = Redis(host=config.redis.host, port=config.redis.port, db=0)
        redis_client.set(scan_uuid, result)
        redis_client.close()

        # Call a method for storing the data
        activities = EasyEasmActivities(RedisConfig(config.redis.host), Neo4jConfig(config.neo4j.password))
        await activities.store_result_to_neo4j(scan_uuid, ["example.com", "www.example.com", "scanme.nmap.org"])

        # Check the content of the Neo4j database
        neo4j_client = GraphDatabase.driver(
            config.neo4j.bolt, auth=basic_auth(config.neo4j.user, password=config.neo4j.password)
        )

        with neo4j_client.session() as session:
            sv_query = """
            MATCH (sv:SoftwareVersion)
            RETURN COUNT(sv) AS count
            """
            sv_result = session.run(sv_query).data()[0]["count"]

            ns_query = """
            MATCH (ns:NetworkService)
            RETURN COUNT(ns) AS count
            """
            ns_result = session.run(ns_query).data()[0]["count"]

            ip_query = """
            MATCH (ip:IP)
            RETURN COUNT(ip) AS count
            """
            ip_result = session.run(ip_query).data()[0]["count"]

            domain_result = """
            MATCH (d:DomainName)
            RETURN COUNT(d) AS count
            """
            domain_result = session.run(domain_result).data()[0]["count"]

            ip_list_query = """
            MATCH (ip:IP)
            RETURN ip.address AS ip
            """
            ip_list_result = session.run(ip_list_query).data()

            sv_list_query = """
            MATCH (sv:SoftwareVersion)
            RETURN sv AS sv
            """
            sv_list_result = session.run(sv_list_query).data()

        neo4j_client.close()

        # Assert equals
        assert sv_result == 4
        assert ns_result == 2
        assert ip_result == 3
        assert domain_result == 3
        assert ip_list_result == [{"ip": "23.192.228.80"}, {"ip": "2.17.147.80"}, {"ip": "45.33.32.156"}]
        assert sv_list_result == [
            {"sv": {"name": "Azure"}},
            {"sv": {"name": "Azure CDN"}},
            {"sv": {"name": "Apache HTTP Server:2.4.7", "version": "apache:http_server:2.4.7"}},
            {"sv": {"name": "Ubuntu", "version": "canonical:ubuntu_linux:*"}},
        ]
