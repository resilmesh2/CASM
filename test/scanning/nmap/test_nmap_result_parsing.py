import xml.etree.ElementTree as ET
from pathlib import Path
from xml.etree.ElementTree import Element

import pytest
from syrupy.assertion import SnapshotAssertion

from temporal.nmap.basic.parser_activities_impl import (
    convert_cpe_to_version_2_3,
    extract_subnet,
    parse_nmap_xml,
)


def load_xml(file_name: str) -> Element:
    xml_path = Path(__file__).parent / "assets" / file_name
    tree = ET.parse(xml_path)
    return tree.getroot()


@pytest.fixture
def metasploitable_nmap_output() -> Element:
    return load_xml("host_down.xml")


@pytest.fixture
def host_down() -> Element:
    return load_xml("host_down.xml")


@pytest.fixture
def host_with_closed_ports() -> Element:
    return load_xml("closed_ports.xml")


@pytest.fixture
def host_without_cpe() -> Element:
    return load_xml("no_cpe.xml")


@pytest.fixture
def multiple_hosts() -> Element:
    return load_xml("multiple_hosts.xml")


@pytest.fixture
def multiple_hostnames() -> Element:
    return load_xml("multiple_hostnames.xml")


class TestExtractSubnet:
    """Test subnet extraction from IP addresses."""

    def test_ipv4_default_prefix(self) -> None:
        assert extract_subnet("192.168.1.10") == "192.168.1.0/24"

    def test_ipv4_custom_prefix(self) -> None:
        assert extract_subnet("10.0.5.100", 16) == "10.0.0.0/16"

    def test_ipv4_slash_32(self) -> None:
        assert extract_subnet("172.16.0.1", 32) == "172.16.0.1/32"

    def test_ipv6_default_prefix(self) -> None:
        assert extract_subnet("2001:db8:85a3::8a2e:370:7334") == "2001:db8:85a3::/64"

    def test_ipv6_custom_prefix(self) -> None:
        assert extract_subnet("2001:db8::1", 48) == "2001:db8::/48"

    def test_invalid_ip(self) -> None:
        assert extract_subnet("not.an.ip.address") is None

    def test_empty_string(self) -> None:
        assert extract_subnet("") is None

    def test_ipv4_edge_cases(self) -> None:
        assert extract_subnet("0.0.0.0") == "0.0.0.0/24"
        assert extract_subnet("255.255.255.255") == "255.255.255.0/24"


class TestConvertCpeToVersion23:
    """Test CPE string conversion to version 2.3 format."""

    def test_basic_cpe_conversion(self) -> None:
        result = convert_cpe_to_version_2_3("cpe:/a:nginx:nginx:1.18.0")
        assert result == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*"

    def test_cpe_with_vendor_product_version(self) -> None:
        result = convert_cpe_to_version_2_3("cpe:/a:apache:http_server:2.4.7")
        assert result == "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*"

    def test_cpe_without_version_returns_none(self) -> None:
        result = convert_cpe_to_version_2_3("cpe:/a:vendor:product")
        assert result is None

    def test_cpe_with_empty_version_returns_none(self) -> None:
        result = convert_cpe_to_version_2_3("cpe:/a:vendor:product:")
        assert result is None

    def test_cpe_operating_system(self) -> None:
        result = convert_cpe_to_version_2_3("cpe:/o:linux:linux_kernel:5.4.0")
        assert result == "cpe:2.3:o:linux:linux_kernel:5.4.0:*:*:*:*:*:*"

    def test_cpe_hardware(self) -> None:
        result = convert_cpe_to_version_2_3("cpe:/h:cisco:router:1.0")
        assert result == "cpe:2.3:h:cisco:router:1.0:*:*:*:*:*:*"

    def test_cpe_with_complex_version(self) -> None:
        result = convert_cpe_to_version_2_3("cpe:/a:wordpress:wordpress:5.8.1")
        assert result == "cpe:2.3:a:wordpress:wordpress:5.8.1:*:*:*:*:*:*"

    def test_cpe_only_part_type(self) -> None:
        result = convert_cpe_to_version_2_3("cpe:/a")
        assert result is None


class TestParseNmapXml:
    """Test full nmap XML parsing."""

    def test_parse_sample_nmap_xml(self, metasploitable_nmap_output: Element, snapshot: SnapshotAssertion) -> None:
        results = parse_nmap_xml(metasploitable_nmap_output, tag=["test-scan"])
        assert snapshot == results

    def test_parse_host_down(self, host_down: Element, snapshot: SnapshotAssertion) -> None:
        results = parse_nmap_xml(host_down, tag=["down"])
        assert results == snapshot

    def test_parse_host_with_closed_ports(self, host_with_closed_ports: Element, snapshot: SnapshotAssertion) -> None:
        results = parse_nmap_xml(host_with_closed_ports, tag=["filtered"])
        # Should only have one application for the open port
        assert results == snapshot

    def test_parse_host_without_cpe(self, host_without_cpe: Element, snapshot: SnapshotAssertion) -> None:
        results = parse_nmap_xml(host_without_cpe, tag=["no-cpe"])
        assert results == snapshot

    def test_multiple_hosts(self, multiple_hosts: Element, snapshot: SnapshotAssertion) -> None:
        results = parse_nmap_xml(multiple_hosts, tag=["multi-host"])
        assert results == snapshot

    def test_multiple_hostnames(self, multiple_hostnames: Element, snapshot: SnapshotAssertion) -> None:
        results = parse_nmap_xml(multiple_hostnames, tag=["multi-hostname"])
        assert results == snapshot
