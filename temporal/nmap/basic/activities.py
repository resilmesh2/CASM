from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict
from typing import Any
from xml.etree import ElementTree

import httpx
import nmap3

from config import ISIMConfig, NmapBasicConfig
from temporal.lib import util
from temporal.nmap.basic import parser_activities_impl
from temporal.nmap.basic.dtos import NmapResults
from temporalio import activity


class NmapBasicActivities:
    def __init__(self, isim_config: ISIMConfig) -> None:
        self.isim_config = isim_config

    @activity.defn
    async def nmap_basic_validate_input(self, input_: dict[str, Any]) -> NmapBasicConfig:
        obj_input = NmapBasicConfig(**input_)
        if not all(map(util.validate_input_hostname, obj_input.targets)):
            raise ValueError("Invalid targets!")
        return obj_input

    @activity.defn
    async def run_basic_nmap_scan(self, targets: list[str], arguments: str) -> ElementTree:
        nmap_client = nmap3.Nmap()
        delimiter = " "
        target = delimiter.join(targets)
        scan_args = arguments

        return ElementTree.tostring(nmap_client.scan_command(target=target, arg=scan_args), encoding="utf8")

    @activity.defn
    async def parse_nmap_xml(self, nmap_output: str, tag: list[str]) -> NmapResults:
        xml_nmap_output = ElementTree.fromstring(nmap_output)
        return parser_activities_impl.parse_nmap_xml(xml_nmap_output, tag)

    @activity.defn
    async def send_result_to_api(self, parsed_nmap_results: NmapResults):
        payload = asdict(parsed_nmap_results)
        headers = {"Content-Type": "application/json"}

        async with httpx.AsyncClient() as conn:
            return (await conn.post(f"{self.isim_config.url}/assets", json=payload, headers=headers)).text

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.parse_nmap_xml, self.run_basic_nmap_scan, self.send_result_to_api, self.nmap_basic_validate_input]
