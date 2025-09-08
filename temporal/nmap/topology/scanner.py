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
    Get source ip(my ip)
    :return: IP if request was successful, empty string otherwise
    """
    try:
        return urllib.request.urlopen("https://ident.me").read().decode("utf8")
    except URLError:
        return ""


def topology_scan_neo(targets, logger=structlog.get_logger()):
    """
    Gets IP ranges to be scanned from IP set on the basis of given index.
    :param targets: list of networks/machines to be scanned
    :param logger: just logger
    :return: informations about scans in dictionary
    """
    logger.info("Topology scanner started.")
    nm = nmap3.Nmap()
    my_ip = get_ip()
    if os.getuid() != 0:
        logger.warning("Nmap traceroute typically require root permissions")
    connections = {
        "data": [],
        "time": datetime.datetime.now().replace(microsecond=0).isoformat()
    }

    for target in targets:
        logger.info(f"Topology scan of {target} started.")
        raw_command = nm.default_command() + f" -sn -n --traceroute {target}"
        split_command = shlex.split(raw_command)
        nmap_results = nm.run_command(split_command)
        root = ET.ElementTree(ET.fromstring(nmap_results)).getroot()

        for host in root.iter("host"):
            prev_ip = my_ip
            trace = host.find("trace")
            connection = {
                "dst_ip": host.find("address").get("addr"),
                "hops": []
            }

            prev_ttl = 0
            if ET.iselement(trace):  # host executing the script does not have trace element
                for route in trace:
                    ttl = int(route.get("ttl"))
                    ip = route.get("ipaddr")
                    data = {"prev_ip": prev_ip,
                            "hops": ttl - prev_ttl,
                            "next_ip": ip}
                    connection["hops"].append(data)
                    prev_ttl = ttl
                    prev_ip = ip

            connections["data"].append(connection)
        logger.info(f"Topology scan of {target} succeeded.")
    return connections
