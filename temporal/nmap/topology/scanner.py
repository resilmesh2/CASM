"""
Module responsible for network topology mapping
"""

import shlex
import urllib.request
import xml.etree.ElementTree as ET  # noqa: S405
from typing import Any
from urllib.error import URLError

import nmap3
import structlog
from nmap3 import exceptions as nmap_exceptions

from temporal.nmap.topology import dtos


class NmapResultParsingError(Exception): ...


def get_ip() -> str:
    """
    Retrieve the public source IP address of the current machine.

    The function queries https://ident.me and returns the response as a string.

    :return: Public IP address as a string if the request succeeds, otherwise an empty string.
    """
    try:
        return urllib.request.urlopen("https://ident.me").read().decode("utf8")
    except URLError:
        return ""


def parse_nmap_results(nmap_results: str, target: str, my_ip: str, logger: Any) -> list[dtos.ConnectionData]:
    """
    Parse nmap XML output to extract network topology and traceroute information.

    This function parses the XML results from a nmap traceroute scan and constructs
    ConnectionData objects containing destination IPs and the hop-by-hop path taken
    to reach each host.

    :param nmap_results: Raw XML output string from nmap command execution.
    :param target: The target network/host that was scanned (used for logging).
    :param my_ip: The source IP address (starting point for traceroute paths).
    :param logger: Logger instance for error and warning messages.
    :return: List of ConnectionData objects, each containing a destination IP and its hop path.
             Returns an empty list if XML parsing fails or no hosts are found.
     """
    connections_data: list[dtos.ConnectionData] = []
    root = ET.ElementTree(ET.fromstring(nmap_results)).getroot()  # noqa: S314

    if root is None:
        logger.error(f"Failed to parse XML root for {target}")
        return []

    for host in root.iter("host"):
        prev_ip = my_ip
        trace = host.find("trace")
        address_elem = host.find("address")

        if address_elem is None:
            logger.warning(f"No address element found for a host in {target}")
            continue

        connection = dtos.ConnectionData(dst_ip=address_elem.get("addr"))

        prev_ttl = 0
        if ET.iselement(trace):  # host executing the script does not have trace element
            for route in trace:
                ttl_str = route.get("ttl")
                ip = route.get("ipaddr")

                if ttl_str is None or ip is None:
                    logger.warning(f"Missing ttl or ipaddr in route for {target}")
                    continue

                ttl = int(ttl_str)
                data = dtos.HopData(prev_ip=prev_ip, hops=(ttl - prev_ttl), next_ip=ip)
                connection.hops.append(data)
                prev_ttl = ttl
                prev_ip = ip

        connections_data.append(connection)

    return connections_data


def topology_scan_neo(targets: list[str]) -> dtos.ScanResult:
    """
    Perform a nmap ping scan with traceroute against the given targets and extract hop paths.

    This function runs nmap with "-sn -n --traceroute" for each target and parses the XML output
    to build a list of connections with hop counts between the local machine and each destination.

    :param targets: List of networks/hosts (IPs, hostnames, or CIDR ranges) to be scanned.
    :return: Dictionary with keys:
             - "time": ISO8601 timestamp of when the scan executed.
             - "data": List of connection dicts with keys "dst_ip" and "hops".
    """
    logger = structlog.get_logger()
    logger.info("Topology scanner started.")
    nm = nmap3.Nmap()
    my_ip = get_ip()
    connections = dtos.ScanResult()

    if not my_ip:
        logger.error("Failed to retrieve public IP address")
        return connections

    for target in targets:
        logger.info(f"Topology scan of {target} started.")
        try:
            raw_command = nm.default_command() + f" -sn -n --traceroute {target}"
            split_command = shlex.split(raw_command)
            nmap_results = nm.run_command(split_command)

            if not nmap_results:
                logger.error(f"Nmap command returned empty results for {target}")
                continue

            connections.data = parse_nmap_results(nmap_results, target, my_ip, logger)

            logger.info(f"Topology scan of {target} succeeded.")

        except ET.ParseError as e:
            logger.exception(f"XML parsing error for {target}: {e}")
        except (nmap_exceptions.NmapExecutionError, nmap_exceptions.NmapNotInstalledError) as e:
            logger.exception(f"Error scanning {target}: {e}")

    return connections
