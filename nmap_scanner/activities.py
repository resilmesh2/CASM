import http
import json
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

import nmap3
from neo4j import GraphDatabase, basic_auth

from easyeasm_demo.config import Neo4jConfig, NmapConfig, RedisConfig, ISIMConfig
from nmap_scanner import parser_activities_impl
from nmap_scanner.dtos import NmapResults
from temporalio import activity


class NmapActivities:
    def __init__(self, nmap_config: NmapConfig, neo4j_config: Neo4jConfig, isim_config: ISIMConfig) -> None:
        self.nmap_config = nmap_config
        self.neo4j_config = neo4j_config
        self.isim_config = isim_config

    @activity.defn
    async def run_nmap_scan(self) -> ElementTree:
        nmap_client = nmap3.Nmap()
        delimiter = " "
        target = delimiter.join(self.nmap_config.targets)
        scan_args = self.nmap_config.arguments

        return ElementTree.tostring(nmap_client.scan_command(target=target, arg=scan_args), encoding="utf8")

    @activity.defn
    async def parse_nmap_xml(self, nmap_output: str) -> NmapResults:
        xml_nmap_output = ElementTree.fromstring(nmap_output)
        return parser_activities_impl.parse_nmap_xml(xml_nmap_output, self.nmap_config.tag)

    @activity.defn
    async def send_result_to_api(self, parsed_nmap_results: NmapResults):
        parsed = urlparse(self.isim_config.url)
        payload = json.dumps(asdict(parsed_nmap_results))
        headers = {"Content-Type": "application/json"}


        with http.client.HTTPConnection(parsed.hostname, parsed.port) as conn:
            conn.request("POST", parsed.path, body=payload, headers=headers)
            with conn.getresponse() as response:
                data = response.read().decode()
                return json.loads(data) if data else None
    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.parse_nmap_xml, self.run_nmap_scan, self.send_result_to_api]
