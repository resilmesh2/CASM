from collections.abc import Awaitable, Callable, Sequence
from typing import Any
from xml.etree import ElementTree

import nmap3

from easyeasm_demo.config import NmapConfig
from nmap_scanner import parser_activities_impl
from nmap_scanner.dtos import NmapResults
from temporalio import activity


class NmapActivities:
    def __init__(self, nmap_config: NmapConfig) -> None:
        self.nmap_config = nmap_config

    @activity.defn
    async def run_nmap_scan(self) -> ElementTree:
        nmap_client = nmap3.Nmap()

        target = self.nmap_config.targets.split(" ")
        scan_args = self.nmap_config.arguments

        return nmap_client.scan_command(target=target, arg=scan_args)

    @activity.defn
    async def parse_nmap_xml(self, nmap_output: ElementTree) -> NmapResults:
        return parser_activities_impl.parse_nmap_xml(nmap_output, self.nmap_config.tag)
    #
    # @activity.defn
    # async def store_results_in_neo4j(self, parsed_nmap_results: ElementTree) -> NmapResults:
    #     return parser_activities_impl.parse_nmap_xml(parsed_nmap_results, [])

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.run_nmap_scan, self.parse_nmap_xml]
