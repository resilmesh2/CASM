"""
Module responsible for network topology mapping
"""

import datetime
import os
import shlex
import urllib.request
import xml.etree.ElementTree as ET
from urllib.error import URLError

import nmap3
import structlog


def get_ip():
    """
    Retrieve the public source IP address of the current machine.

    The function queries https://ident.me and returns the response as a string.

    :return: Public IP address as a string if the request succeeds, otherwise an empty string.
    """
    try:
        return urllib.request.urlopen("https://ident.me").read().decode("utf8")
    except URLError:
        return ""


def topology_scan_neo(targets: list[str], logger=structlog.get_logger()):
    """
    Perform a nmap ping scan with traceroute against the given targets and extract hop paths.

    This function runs nmap with "-sn -n --traceroute" for each target and parses the XML output
    to build a list of connections with hop counts between the local machine and each destination.

    :param targets: List of networks/hosts (IPs, hostnames, or CIDR ranges) to be scanned.
    :param logger: Logger instance used for progress messages.
    :return: Dictionary with keys:
             - "time": ISO8601 timestamp of when the scan executed.
             - "data": List of connection dicts with keys "dst_ip" and "hops".
    """
    logger.info("Topology scanner started.")
    nm = nmap3.Nmap()
    my_ip = get_ip()
    if os.getuid() != 0:
        logger.warning("Nmap traceroute typically require root permissions")
    connections = {"data": [], "time": datetime.datetime.now().replace(microsecond=0).isoformat()}

    for target in targets:
        logger.info(f"Topology scan of {target} started.")
        raw_command = nm.default_command() + f" -sn -n --traceroute {target}"
        split_command = shlex.split(raw_command)
        nmap_results = nm.run_command(split_command)
        root = ET.ElementTree(ET.fromstring(nmap_results)).getroot()

        for host in root.iter("host"):
            prev_ip = my_ip
            trace = host.find("trace")
            connection = {"dst_ip": host.find("address").get("addr"), "hops": []}

            prev_ttl = 0
            if ET.iselement(trace):  # host executing the script does not have trace element
                for route in trace:
                    ttl = int(route.get("ttl"))
                    ip = route.get("ipaddr")
                    data = {"prev_ip": prev_ip, "hops": ttl - prev_ttl, "next_ip": ip}
                    connection["hops"].append(data)
                    prev_ttl = ttl
                    prev_ip = ip

            connections["data"].append(connection)
        logger.info(f"Topology scan of {target} succeeded.")
    return connections
