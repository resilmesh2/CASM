from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict
from typing import Any
from xml.etree import ElementTree

import httpx
import nmap3
from temporalio import activity

from config import ISIMConfig, NmapBasicConfig
from temporal.lib import util
from temporal.nmap.basic import parser_activities_impl
from temporal.nmap.basic.dtos import NmapResults


class NmapBasicActivities:
    """
    Activities to run a basic nmap scan, parse results, and publish them to ISIM.
    """

    def __init__(self, isim_config: ISIMConfig) -> None:
        self.isim_config = isim_config

    @activity.defn
    async def nmap_basic_validate_input(self, input_: dict[str, Any]) -> NmapBasicConfig:
        """
        Validate and normalize the incoming nmap basic scan configuration.

        :param input_: Mapping with fields expected by NmapBasicConfig (e.g., targets, arguments, tag).
        :return: A validated NmapBasicConfig instance.
        :raises ValueError: If any provided target hostname/IP is invalid.
        """
        obj_input = NmapBasicConfig(**input_)
        if not all(map(util.validate_input_hostname, obj_input.targets)):
            raise ValueError("Invalid targets!")
        return obj_input

    @activity.defn
    async def run_basic_nmap_scan(self, targets: list[str], arguments: str) -> ElementTree:
        """
        Execute a nmap scan with the provided targets and raw argument string.

        :param targets: List of hostnames or IPs to scan.
        :param arguments: Additional command-line arguments passed to nmap.
        :return: XML output returned by nmap as a UTF-8 encoded bytes string.
        """
        nmap_client = nmap3.Nmap()
        delimiter = " "
        target = delimiter.join(targets)
        scan_args = arguments

        return ElementTree.tostring(nmap_client.scan_command(target=target, arg=scan_args), encoding="utf8")

    @activity.defn
    async def parse_nmap_xml(self, nmap_output: str, tag: list[str]) -> NmapResults:
        """
        Parse raw nmap XML into structured results suitable for ISIM ingestion.

        :param nmap_output: XML content produced by nmap (string with XML).
        :param tag: List of tag strings to annotate parsed entities.
        :return: NmapResults data structure with hosts, devices, applications, and versions.
        """
        xml_nmap_output = ElementTree.fromstring(nmap_output)
        return parser_activities_impl.parse_nmap_xml(xml_nmap_output, tag)

    @activity.defn
    async def send_result_to_api(self, parsed_nmap_results: NmapResults):
        """
        Send parsed nmap results to the ISIM API.

        :param parsed_nmap_results: The structured results are produced by parse_nmap_xml.
        :return: The response body is returned by the ISIM API.
        """
        payload = asdict(parsed_nmap_results)
        headers = {"Content-Type": "application/json"}

        async with httpx.AsyncClient() as conn:
            return (await conn.post(f"{self.isim_config.url}/assets", json=payload, headers=headers)).text

    def get_activities(self) -> Sequence[Callable[..., Awaitable[Any]]]:
        return [self.parse_nmap_xml, self.run_basic_nmap_scan, self.send_result_to_api, self.nmap_basic_validate_input]
