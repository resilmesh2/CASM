"""
Module for Integrating CVE Data with Neo4j

This module provides functions to integrate and update vulnerability (CVE) data into a Neo4j
graph database. It uses a CVEConnectorClient to interact with the Neo4j instance and supports
creating new CVE nodes, updating existing nodes, and establishing relationships between vulnerabilities
and associated software versions. In addition, the module includes helper functions for parsing CPE strings,
checking version ranges, and processing configuration data to determine software associations relevant to a
vulnerability.

Functions:
  - move_cve_data_to_neo4j: Inserts or updates vulnerability data in the Neo4j database based on a list of Vulnerability objects.
  - parse_cpe: Parses a full CPE string into its vendor, product, and version components.
  - check_ranges: Determines if a given software version falls within specified version boundaries.
  - check_configurations: Processes CPE configurations to decide if a vulnerability node should be created or updated.
  - process_nvd_cpe: Processes an individual CPE match entry and creates relationships between vulnerabilities and software versions.
  - parse_cpe, check_ranges, check_configurations, process_nvd_cpe: Helper functions used in processing and integrating CVE data.

Dependencies:
  - CVEConnectorClient from cve_connector.nvd_cve.CveConnectorClient_new_version for Neo4j interactions.
  - Vulnerability from cve_connector.nvd_cve.vulnerability.
  - re, logging modules.
"""

import logging
import re
import time
from typing import Any

import requests
from packaging.version import Version

from cve_connector.nvd_cve.cpe_identifier import CpeIdentifier
from cve_connector.nvd_cve.CveConnectorClient import CVEConnectorClient
from cve_connector.nvd_cve.vulnerability import Vulnerability


def move_cve_data_to_neo4j(
    vulnerability_list: list[Vulnerability],
    cpe: str,
    neo4j_passwd: str,
    nvd_api_key: str | None = None,
    bolt: str = "bolt://localhost:7687",
    user: str = "neo4j",
) -> None:
    """
    Moves CVE data from Vulnerability objects into a Neo4j database.

    Iterates over Vulnerability objects, checking if CVEs exist in Neo4j. Creates new CVE nodes
    or updates existing ones, and establishes relationships with software versions.

    :param vulnerability_list: List of Vulnerability objects.
    :param cpe: String representation of CPE identifier.
    :param neo4j_passwd: Password for Neo4j authentication.
    :param nvd_api_key: Neo4j API key. Defaults to None.
    :param bolt: Bolt connection string. Defaults to "bolt://localhost:7687".
    :param user: Username for Neo4j. Defaults to "neo4j".
    :return: None
    """
    client = CVEConnectorClient(password=neo4j_passwd, bolt=bolt, user=user)
    cve_count_created = 0
    cve_count_updated = 0
    for vulnerability in vulnerability_list:
        vul_description = f"Assumed vulnerability with ID {vulnerability.cve}"
        if not client.cve_exists(vulnerability.cve):
            client.create_new_vulnerability(vul_description)
            client.create_relationship_between_vulnerability_and_software_version(vul_description, cpe)
            client.create_cve_from_nvd(
                cve_id=vulnerability.cve,
                description=vulnerability.description,
                cwe=list(vulnerability.cwe),
                vector_string_v2=vulnerability.cvssv2.get("vectorString"),
                access_vector_v2=vulnerability.cvssv2.get("accessVector"),
                access_complexity_v2=vulnerability.cvssv2.get("accessComplexity"),
                authentication_v2=vulnerability.cvssv2.get("authentication"),
                confidentiality_impact_v2=vulnerability.cvssv2.get("confidentialityImpact"),
                integrity_impact_v2=vulnerability.cvssv2.get("integrityImpact"),
                availability_impact_v2=vulnerability.cvssv2.get("availabilityImpact"),
                base_score_v2=vulnerability.cvssv2.get("baseScore"),
                base_severity_v2=vulnerability.cvssv2.get("baseSeverity"),
                exploitability_score_v2=vulnerability.cvssv2.get("exploitabilityScore"),
                impact_score_v2=vulnerability.cvssv2.get("impactScore"),
                ac_insuf_info_v2=vulnerability.cvssv2.get("acInsufInfo"),
                obtain_all_privilege_v2=vulnerability.cvssv2.get("obtainAllPrivilege"),
                obtain_user_privilege_v2=vulnerability.cvssv2.get("obtainUserPrivilege"),
                obtain_other_privilege_v2=vulnerability.cvssv2.get("obtainOtherPrivilege"),
                user_interaction_required_v2=vulnerability.cvssv2.get("userInteractionRequired"),
                vector_string_v30=vulnerability.cvssv30.get("vectorString"),
                attack_vector_v30=vulnerability.cvssv30.get("attackVector"),
                attack_complexity_v30=vulnerability.cvssv30.get("attackComplexity"),
                privileges_required_v30=vulnerability.cvssv30.get("privilegesRequired"),
                user_interaction_v30=vulnerability.cvssv30.get("userInteraction"),
                scope_v30=vulnerability.cvssv30.get("scope"),
                confidentiality_impact_v30=vulnerability.cvssv30.get("confidentialityImpact"),
                integrity_impact_v30=vulnerability.cvssv30.get("integrityImpact"),
                availability_impact_v30=vulnerability.cvssv30.get("availabilityImpact"),
                base_score_v30=vulnerability.cvssv30.get("baseScore"),
                base_severity_v30=vulnerability.cvssv30.get("baseSeverity"),
                exploitability_score_v30=vulnerability.cvssv30.get("exploitabilityScore"),
                impact_score_v30=vulnerability.cvssv30.get("impactScore"),
                vector_string_v31=vulnerability.cvssv31.get("vectorString"),
                attack_vector_v31=vulnerability.cvssv31.get("attackVector"),
                attack_complexity_v31=vulnerability.cvssv31.get("attackComplexity"),
                privileges_required_v31=vulnerability.cvssv31.get("privilegesRequired"),
                user_interaction_v31=vulnerability.cvssv31.get("userInteraction"),
                scope_v31=vulnerability.cvssv31.get("scope"),
                confidentiality_impact_v31=vulnerability.cvssv31.get("confidentialityImpact"),
                integrity_impact_v31=vulnerability.cvssv31.get("integrityImpact"),
                availability_impact_v31=vulnerability.cvssv31.get("availabilityImpact"),
                base_score_v31=vulnerability.cvssv31.get("baseScore"),
                base_severity_v31=vulnerability.cvssv31.get("baseSeverity"),
                exploitability_score_v31=vulnerability.cvssv31.get("exploitabilityScore"),
                impact_score_v31=vulnerability.cvssv31.get("impactScore"),
                vector_string_v40=vulnerability.cvssv40.get("vectorString"),
                attack_vector_v40=vulnerability.cvssv40.get("attackVector"),
                attack_complexity_v40=vulnerability.cvssv40.get("attackComplexity"),
                attack_requirements_v40=vulnerability.cvssv40.get("attackRequirements"),
                privileges_required_v40=vulnerability.cvssv40.get("privilegesRequired"),
                user_interaction_v40=vulnerability.cvssv40.get("userInteraction"),
                vulnerable_system_confidentiality_v40=vulnerability.cvssv40.get("vulnerableSystemConfidentiality"),
                vulnerable_system_integrity_v40=vulnerability.cvssv40.get("vulnerableSystemIntegrity"),
                vulnerable_system_availability_v40=vulnerability.cvssv40.get("vulnerableSystemAvailability"),
                subsequent_system_confidentiality_v40=vulnerability.cvssv40.get("subsequentSystemConfidentiality"),
                subsequent_system_integrity_v40=vulnerability.cvssv40.get("subsequentSystemIntegrity"),
                subsequent_system_availability_v40=vulnerability.cvssv40.get("subsequentSystemAvailability"),
                exploit_maturity_v40=vulnerability.cvssv40.get("exploitMaturity"),
                base_score_v40=vulnerability.cvssv40.get("baseScore"),
                base_severity_v40=vulnerability.cvssv40.get("baseSeverity"),
                cpe_type=list(vulnerability.cpe_type),
                ref_tags=list(vulnerability.ref_tag),
                published=vulnerability.published,
                last_modified=vulnerability.lastModified,
                result_impacts=vulnerability.result_impacts,
            )
            client.create_relationship_between_cve_and_vulnerability(vulnerability.cve, vul_description)
            cve_count_created += 1
        else:
            client.update_cve_from_nvd(
                cve_id=vulnerability.cve,
                description=vulnerability.description,
                cwe=list(vulnerability.cwe),
                vector_string_v2=vulnerability.cvssv2.get("vectorString"),
                access_vector_v2=vulnerability.cvssv2.get("accessVector"),
                access_complexity_v2=vulnerability.cvssv2.get("accessComplexity"),
                authentication_v2=vulnerability.cvssv2.get("authentication"),
                confidentiality_impact_v2=vulnerability.cvssv2.get("confidentialityImpact"),
                integrity_impact_v2=vulnerability.cvssv2.get("integrityImpact"),
                availability_impact_v2=vulnerability.cvssv2.get("availabilityImpact"),
                base_score_v2=vulnerability.cvssv2.get("baseScore"),
                base_severity_v2=vulnerability.cvssv2.get("baseSeverity"),
                exploitability_score_v2=vulnerability.cvssv2.get("exploitabilityScore"),
                impact_score_v2=vulnerability.cvssv2.get("impactScore"),
                ac_insuf_info_v2=vulnerability.cvssv2.get("acInsufInfo"),
                obtain_all_privilege_v2=vulnerability.cvssv2.get("obtainAllPrivilege"),
                obtain_user_privilege_v2=vulnerability.cvssv2.get("obtainUserPrivilege"),
                obtain_other_privilege_v2=vulnerability.cvssv2.get("obtainOtherPrivilege"),
                user_interaction_required_v2=vulnerability.cvssv2.get("userInteractionRequired"),
                vector_string_v30=vulnerability.cvssv30.get("vectorString"),
                attack_vector_v30=vulnerability.cvssv30.get("attackVector"),
                attack_complexity_v30=vulnerability.cvssv30.get("attackComplexity"),
                privileges_required_v30=vulnerability.cvssv30.get("privilegesRequired"),
                user_interaction_v30=vulnerability.cvssv30.get("userInteraction"),
                scope_v30=vulnerability.cvssv30.get("scope"),
                confidentiality_impact_v30=vulnerability.cvssv30.get("confidentialityImpact"),
                integrity_impact_v30=vulnerability.cvssv30.get("integrityImpact"),
                availability_impact_v30=vulnerability.cvssv30.get("availabilityImpact"),
                base_score_v30=vulnerability.cvssv30.get("baseScore"),
                base_severity_v30=vulnerability.cvssv30.get("baseSeverity"),
                exploitability_score_v30=vulnerability.cvssv30.get("exploitabilityScore"),
                impact_score_v30=vulnerability.cvssv30.get("impactScore"),
                vector_string_v31=vulnerability.cvssv31.get("vectorString"),
                attack_vector_v31=vulnerability.cvssv31.get("attackVector"),
                attack_complexity_v31=vulnerability.cvssv31.get("attackComplexity"),
                privileges_required_v31=vulnerability.cvssv31.get("privilegesRequired"),
                user_interaction_v31=vulnerability.cvssv31.get("userInteraction"),
                scope_v31=vulnerability.cvssv31.get("scope"),
                confidentiality_impact_v31=vulnerability.cvssv31.get("confidentialityImpact"),
                integrity_impact_v31=vulnerability.cvssv31.get("integrityImpact"),
                availability_impact_v31=vulnerability.cvssv31.get("availabilityImpact"),
                base_score_v31=vulnerability.cvssv31.get("baseScore"),
                base_severity_v31=vulnerability.cvssv31.get("baseSeverity"),
                exploitability_score_v31=vulnerability.cvssv31.get("exploitabilityScore"),
                impact_score_v31=vulnerability.cvssv31.get("impactScore"),
                vector_string_v40=vulnerability.cvssv40.get("vectorString"),
                attack_vector_v40=vulnerability.cvssv40.get("attackVector"),
                attack_complexity_v40=vulnerability.cvssv40.get("attackComplexity"),
                attack_requirements_v40=vulnerability.cvssv40.get("attackRequirements"),
                privileges_required_v40=vulnerability.cvssv40.get("privilegesRequired"),
                user_interaction_v40=vulnerability.cvssv40.get("userInteraction"),
                vulnerable_system_confidentiality_v40=vulnerability.cvssv40.get("vulnerableSystemConfidentiality"),
                vulnerable_system_integrity_v40=vulnerability.cvssv40.get("vulnerableSystemIntegrity"),
                vulnerable_system_availability_v40=vulnerability.cvssv40.get("vulnerableSystemAvailability"),
                subsequent_system_confidentiality_v40=vulnerability.cvssv40.get("subsequentSystemConfidentiality"),
                subsequent_system_integrity_v40=vulnerability.cvssv40.get("subsequentSystemIntegrity"),
                subsequent_system_availability_v40=vulnerability.cvssv40.get("subsequentSystemAvailability"),
                exploit_maturity_v40=vulnerability.cvssv40.get("exploitMaturity"),
                base_score_v40=vulnerability.cvssv40.get("baseScore"),
                base_severity_v40=vulnerability.cvssv40.get("baseSeverity"),
                cpe_type=list(vulnerability.cpe_type),
                ref_tags=list(vulnerability.ref_tag),
                published=vulnerability.published,
                last_modified=vulnerability.lastModified,
                result_impacts=vulnerability.result_impacts,
            )
            client.create_relationship_between_cve_and_vulnerability(vulnerability.cve, vul_description)
            cve_count_updated += 1
    logging.info(f"Created {cve_count_created} CVEs, updated {cve_count_updated} CVEs")


def check_ranges(cpe_match: dict[str, Any], version: str, nvd_api_key: str) -> bool:
    """
    Checks if a software version falls within the specified version range.

    Uses semantic versioning for comparison if possible, falling back to string comparison.

    :param cpe_match: Dictionary with version range keys (e.g., 'versionStartIncluding').
    :param version: Software version to check.
    :param nvd_api_key: API key for NVD REST API.
    :return: True if version is within range; False otherwise.
    """
    logging.info(f"Checking CPE range: {cpe_match}")
    if CpeIdentifier.from_string(cpe_match["criteria"]).version != "*":
        raise ValueError(f"Invalid CPE range containing version number: {cpe_match}")

    if (
        "versionStartIncluding" in cpe_match
        or "versionStartExcluding" in cpe_match
        or "versionEndIncluding" in cpe_match
        or "versionEndExcluding" in cpe_match
    ):
        result = False
        current_version = Version(version)
        if "versionStartIncluding" in cpe_match:
            condition = Version(cpe_match["versionStartIncluding"])
            if current_version < condition:
                return False
            result = True
        if "versionStartExcluding" in cpe_match:
            condition = Version(cpe_match["versionStartExcluding"])
            if current_version <= condition:
                return False
            result = True
        if "versionEndIncluding" in cpe_match:
            condition = Version(cpe_match["versionEndIncluding"])
            if current_version > condition:
                return False
            result = True
        if "versionEndExcluding" in cpe_match:
            condition = Version(cpe_match["versionEndExcluding"])
            if current_version >= condition:
                return False
            result = True
        logging.info(f"Successful check CPE range: {cpe_match}")
        return result

    # CPE has * (ANY) as a version, but does not have any indication of start and end - matchCriteriaId should be used
    url = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
    params = {"matchCriteriaId": f"{cpe_match['matchCriteriaId']}"}
    headers = {"apiKey": nvd_api_key} if nvd_api_key else None
    response = requests.get(url, headers=headers, params=params)

    # the official documentation recommends to pause scripts for 6 seconds after each request
    time.sleep(6)
    if response.status_code == 200:
        data = response.json()
        for match_string in data["matchStrings"]:
            for match in match_string["matchString"]["matches"]:
                if CpeIdentifier.from_string(match["cpeName"]).version == version:
                    logging.info(f"Successful check of CPE range: {cpe_match} and version: {match['cpeName']}")
                    return True
    return False


def check_configurations(
    client: CVEConnectorClient,
    cpe_configurations: list[dict[str, Any]],
    vul_description: str,
    flag: bool,
    nvd_api_key: str,
) -> bool:
    """
    Processes CPE configurations to determine if a vulnerability node should be created or updated.

    Handles 'AND' and 'OR' operators in configurations, processing CPE matches to create relationships.

    :param client: CVEConnectorClient for Neo4j interactions.
    :param cpe_configurations: Configuration data for the vulnerability.
    :param vul_description: Vulnerability description.
    :param flag: Indicates if a vulnerability node was created.
    :param nvd_api_key: API key for NVD REST API.
    :return: Updated flag indicating if a vulnerability node was created.
    :raises ValueError: If configuration structure is invalid.
    """
    create_vulnerability = flag
    for configuration in cpe_configurations:
        if "operator" in configuration:
            if configuration["operator"] == "AND":
                if len(configuration.get("nodes", [])) == 2:
                    nodes = configuration["nodes"]
                    vuln_node = nodes[0] if nodes[0].get("cpeMatch", [{}])[0].get("vulnerable") else nodes[1]
                    non_vuln_node = nodes[1] if nodes[0].get("cpeMatch", [{}])[0].get("vulnerable") else nodes[0]
                    if vuln_node.get("operator") != "OR" or non_vuln_node.get("operator") != "OR":
                        logging.error("Invalid recursion depth in AND configuration")
                        raise ValueError("Depth of recursion was more than 1")
                    for cpe_item in vuln_node.get("cpeMatch", []):
                        create_vulnerability = process_nvd_cpe(
                            client, cpe_item, vul_description, create_vulnerability, nvd_api_key
                        )
                else:
                    logging.warning(
                        f"Expected two nodes in AND configuration, got {len(configuration.get('nodes', []))}"
                    )
        else:
            for node in configuration.get("nodes", []):
                if node.get("operator", "") == "OR":
                    for cpe_match in node.get("cpeMatch", []):
                        create_vulnerability = process_nvd_cpe(
                            client, cpe_match, vul_description, create_vulnerability, nvd_api_key
                        )
    return create_vulnerability


def process_nvd_cpe(
    client: CVEConnectorClient, cpe_match: dict[str, Any], vul_description: str, flag: bool, nvd_api_key
) -> bool:
    """
    Processes a CPE match to create relationships between vulnerabilities and software versions.
    Uses Cpe dataclass for parsing CPE 2.3 format.
    :param client: CVEConnectorClient for Neo4j interactions.
    :param cpe_match: dictionary of raw data containing CPE match information.
    :param vul_description: description of a Neo4j node of type Vulnerability.
    :param flag: Indicates if a vulnerability node was created.
    :param nvd_api_key: API key for NVD REST API.
    :return: Updated flag indicating if a vulnerability node was created.
    """
    vulnerability_created = flag
    try:
        cpe = CpeIdentifier.from_string(cpe_match["criteria"])
        logging.info(
            f"{vul_description} Processing CPE match for vendor={cpe.vendor}, product={cpe.product}, version={cpe.version}"
        )

        if cpe.version.count(".") > 1:
            match = re.match(r"(?P<major>.*?)\.(?P<minor>.*?)\.(?P<build>.*)", cpe.version)
            shortened_cpe = f"{cpe.vendor}:{cpe.product}:{match.group(1)}.{match.group(2)}"
            if not vulnerability_created:
                vulnerability_created = True
                client.create_new_vulnerability(vul_description)
                client.create_relationship_between_vulnerability_and_software_version(vul_description, shortened_cpe)

        for possible_software_version in [
            f"{cpe.vendor}:{cpe.product}:{cpe.version}",
            f"{cpe.vendor}:{cpe.product}:*",
            f"{cpe.vendor}:*:*",
        ]:
            if client.software_version_exists(possible_software_version):
                if not vulnerability_created:
                    vulnerability_created = True
                    client.create_new_vulnerability(vul_description)
                client.create_relationship_between_vulnerability_and_software_version(
                    vul_description, possible_software_version
                )

        # Other parts of code should be executed only for ANY (*) version
        if cpe.version != "*":
            return vulnerability_created

        vendor_and_product = f"{cpe.vendor}:{cpe.product}"
        sw_versions = [v["software"]["version"] for v in client.get_versions_of_product(vendor_and_product)]

        for sw_version in sw_versions:
            possible_version = sw_version.split(":")[-1]
            if check_ranges(cpe_match, possible_version, nvd_api_key):
                if not vulnerability_created:
                    vulnerability_created = True
                    client.create_new_vulnerability(vul_description)
                client.create_relationship_between_vulnerability_and_software_version(
                    vul_description, f"{cpe.vendor}:{cpe.product}:{possible_version}"
                )

    except Exception as e:
        logging.warning(f"Skipping CPE processing due to error: {e}")

    return vulnerability_created


def get_software_versions_from_neo4j(
    neo4j_passwd: str, bolt: str = "bolt://localhost:7687", user: str = "neo4j"
) -> list[dict[str, Any]]:
    """
    Retrieves all software versions stored in the Neo4j database.

    :param neo4j_passwd: Password for Neo4j authentication.
    :param bolt: Bolt connection string. Defaults to "bolt://localhost:7687".
    :param user: Username for Neo4j. Defaults to "neo4j".
    :return: List of software version strings.
    """
    client = CVEConnectorClient(password=neo4j_passwd, bolt=bolt, user=user)
    return client.get_all_software_versions()


def update_timestamp_for_software_version(
    software_version: str, timestamp: str, neo4j_passwd: str, bolt: str = "bolt://localhost:7687", user: str = "neo4j"
) -> None:
    """
    Creates or updates a timestamp for software version.

    :param software_version: Software version that will be updated.
    :param timestamp: Timestamp of the last retrieval of CVEs from the NVD.
    :param neo4j_passwd: Password to Neo4j database.
    :param bolt: Bolt connection string. Defaults to "bolt://localhost:7687".
    :param user: Username for Neo4j. Defaults to "neo4j".
    :return: None
    """
    client = CVEConnectorClient(password=neo4j_passwd, bolt=bolt, user=user)
    client.update_timestamp_of_software_version(software_version, timestamp)
