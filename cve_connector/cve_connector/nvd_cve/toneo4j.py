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

import re
import logging
import requests
from typing import List, Dict, Any, Tuple
from packaging.version import Version
from cve_connector.nvd_cve.CveConnectorClient import CVEConnectorClient
from cve_connector.nvd_cve.vulnerability import Vulnerability


def move_cve_data_to_neo4j(vulnerability_list: List[Vulnerability], neo4j_passwd: str, nvd_api_key: str,
                           bolt: str = "bolt://localhost:7687", user: str = "neo4j") -> None:
    """
    Moves CVE data from Vulnerability objects into a Neo4j database.

    Iterates over Vulnerability objects, checking if CVEs exist in Neo4j. Creates new CVE nodes
    or updates existing ones, and establishes relationships with software versions.

    :param vulnerability_list: List of Vulnerability objects.
    :param neo4j_passwd: Password for Neo4j authentication.
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
            vulnerability_created = check_configurations(
                client, vulnerability.cpe_configurations,
                vul_description, False, nvd_api_key)
            if vulnerability_created:
                client.create_cve_from_nvd(
                    cve_id=vulnerability.cve,
                    description=vulnerability.description,
                    cwe=list(vulnerability.cwe),
                    vectorString_v2=vulnerability.cvssv2.get("vectorString"),
                    accessVector_v2=vulnerability.cvssv2.get("accessVector"),
                    accessComplexity_v2=vulnerability.cvssv2.get("accessComplexity"),
                    authentication_v2=vulnerability.cvssv2.get("authentication"),
                    confidentialityImpact_v2=vulnerability.cvssv2.get("confidentialityImpact"),
                    integrityImpact_v2=vulnerability.cvssv2.get("integrityImpact"),
                    availabilityImpact_v2=vulnerability.cvssv2.get("availabilityImpact"),
                    baseScore_v2=vulnerability.cvssv2.get("baseScore"),
                    baseSeverity_v2=vulnerability.cvssv2.get("baseSeverity"),
                    exploitabilityScore_v2=vulnerability.cvssv2.get("exploitabilityScore"),
                    impactScore_v2=vulnerability.cvssv2.get("impactScore"),
                    acInsufInfo_v2=vulnerability.cvssv2.get("acInsufInfo"),
                    obtainAllPrivilege_v2=vulnerability.cvssv2.get("obtainAllPrivilege"),
                    obtainUserPrivilege_v2=vulnerability.cvssv2.get("obtainUserPrivilege"),
                    obtainOtherPrivilege_v2=vulnerability.cvssv2.get("obtainOtherPrivilege"),
                    userInteractionRequired_v2=vulnerability.cvssv2.get("userInteractionRequired"),
                    vectorString_v30=vulnerability.cvssv30.get("vectorString"),
                    attackVector_v30=vulnerability.cvssv30.get("attackVector"),
                    attackComplexity_v30=vulnerability.cvssv30.get("attackComplexity"),
                    privilegesRequired_v30=vulnerability.cvssv30.get("privilegesRequired"),
                    userInteraction_v30=vulnerability.cvssv30.get("userInteraction"),
                    scope_v30=vulnerability.cvssv30.get("scope"),
                    confidentialityImpact_v30=vulnerability.cvssv30.get("confidentialityImpact"),
                    integrityImpact_v30=vulnerability.cvssv30.get("integrityImpact"),
                    availabilityImpact_v30=vulnerability.cvssv30.get("availabilityImpact"),
                    baseScore_v30=vulnerability.cvssv30.get("baseScore"),
                    baseSeverity_v30=vulnerability.cvssv30.get("baseSeverity"),
                    exploitabilityScore_v30=vulnerability.cvssv30.get("exploitabilityScore"),
                    impactScore_v30=vulnerability.cvssv30.get("impactScore"),
                    vectorString_v31=vulnerability.cvssv31.get("vectorString"),
                    attackVector_v31=vulnerability.cvssv31.get("attackVector"),
                    attackComplexity_v31=vulnerability.cvssv31.get("attackComplexity"),
                    privilegesRequired_v31=vulnerability.cvssv31.get("privilegesRequired"),
                    userInteraction_v31=vulnerability.cvssv31.get("userInteraction"),
                    scope_v31=vulnerability.cvssv31.get("scope"),
                    confidentialityImpact_v31=vulnerability.cvssv31.get("confidentialityImpact"),
                    integrityImpact_v31=vulnerability.cvssv31.get("integrityImpact"),
                    availabilityImpact_v31=vulnerability.cvssv31.get("availabilityImpact"),
                    baseScore_v31=vulnerability.cvssv31.get("baseScore"),
                    baseSeverity_v31=vulnerability.cvssv31.get("baseSeverity"),
                    exploitabilityScore_v31=vulnerability.cvssv31.get("exploitabilityScore"),
                    impactScore_v31=vulnerability.cvssv31.get("impactScore"),
                    vectorString_v40=vulnerability.cvssv40.get("vectorString"),
                    attackVector_v40=vulnerability.cvssv40.get("attackVector"),
                    attackComplexity_v40=vulnerability.cvssv40.get("attackComplexity"),
                    attackRequirements_v40=vulnerability.cvssv40.get("attackRequirements"),
                    privilegesRequired_v40=vulnerability.cvssv40.get("privilegesRequired"),
                    userInteraction_v40=vulnerability.cvssv40.get("userInteraction"),
                    vulnerableSystemConfidentiality_v40=vulnerability.cvssv40.get("vulnerableSystemConfidentiality"),
                    vulnerableSystemIntegrity_v40=vulnerability.cvssv40.get("vulnerableSystemIntegrity"),
                    vulnerableSystemAvailability_v40=vulnerability.cvssv40.get("vulnerableSystemAvailability"),
                    subsequentSystemConfidentiality_v40=vulnerability.cvssv40.get("subsequentSystemConfidentiality"),
                    subsequentSystemIntegrity_v40=vulnerability.cvssv40.get("subsequentSystemIntegrity"),
                    subsequentSystemAvailability_v40=vulnerability.cvssv40.get("subsequentSystemAvailability"),
                    baseScore_v40=vulnerability.cvssv40.get("baseScore"),
                    baseSeverity_v40=vulnerability.cvssv40.get("baseSeverity"),
                    cpe_type=list(vulnerability.cpe_type),
                    ref_tags=list(vulnerability.ref_tag),
                    published=vulnerability.published,
                    lastModified=vulnerability.lastModified,
                    result_impacts=vulnerability.result_impacts
                )
                client.create_relationship_between_cve_and_vulnerability(vulnerability.cve, vul_description)
                cve_count_created += 1
        else:
            check_configurations(client, vulnerability.cpe_configurations,
                                 vul_description, True, nvd_api_key)
            client.update_cve_from_nvd(
                cve_id=vulnerability.cve,
                description=vulnerability.description,
                cwe=list(vulnerability.cwe),
                vectorString_v2=vulnerability.cvssv2.get("vectorString"),
                accessVector_v2=vulnerability.cvssv2.get("accessVector"),
                accessComplexity_v2=vulnerability.cvssv2.get("accessComplexity"),
                authentication_v2=vulnerability.cvssv2.get("authentication"),
                confidentialityImpact_v2=vulnerability.cvssv2.get("confidentialityImpact"),
                integrityImpact_v2=vulnerability.cvssv2.get("integrityImpact"),
                availabilityImpact_v2=vulnerability.cvssv2.get("availabilityImpact"),
                baseScore_v2=vulnerability.cvssv2.get("baseScore"),
                baseSeverity_v2=vulnerability.cvssv2.get("baseSeverity"),
                exploitabilityScore_v2=vulnerability.cvssv2.get("exploitabilityScore"),
                impactScore_v2=vulnerability.cvssv2.get("impactScore"),
                acInsufInfo_v2=vulnerability.cvssv2.get("acInsufInfo"),
                obtainAllPrivilege_v2=vulnerability.cvssv2.get("obtainAllPrivilege"),
                obtainUserPrivilege_v2=vulnerability.cvssv2.get("obtainUserPrivilege"),
                obtainOtherPrivilege_v2=vulnerability.cvssv2.get("obtainOtherPrivilege"),
                userInteractionRequired_v2=vulnerability.cvssv2.get("userInteractionRequired"),
                vectorString_v30=vulnerability.cvssv30.get("vectorString"),
                attackVector_v30=vulnerability.cvssv30.get("attackVector"),
                attackComplexity_v30=vulnerability.cvssv30.get("attackComplexity"),
                privilegesRequired_v30=vulnerability.cvssv30.get("privilegesRequired"),
                userInteraction_v30=vulnerability.cvssv30.get("userInteraction"),
                scope_v30=vulnerability.cvssv30.get("scope"),
                confidentialityImpact_v30=vulnerability.cvssv30.get("confidentialityImpact"),
                integrityImpact_v30=vulnerability.cvssv30.get("integrityImpact"),
                availabilityImpact_v30=vulnerability.cvssv30.get("availabilityImpact"),
                baseScore_v30=vulnerability.cvssv30.get("baseScore"),
                baseSeverity_v30=vulnerability.cvssv30.get("baseSeverity"),
                exploitabilityScore_v30=vulnerability.cvssv30.get("exploitabilityScore"),
                impactScore_v30=vulnerability.cvssv30.get("impactScore"),
                vectorString_v31=vulnerability.cvssv31.get("vectorString"),
                attackVector_v31=vulnerability.cvssv31.get("attackVector"),
                attackComplexity_v31=vulnerability.cvssv31.get("attackComplexity"),
                privilegesRequired_v31=vulnerability.cvssv31.get("privilegesRequired"),
                userInteraction_v31=vulnerability.cvssv31.get("userInteraction"),
                scope_v31=vulnerability.cvssv31.get("scope"),
                confidentialityImpact_v31=vulnerability.cvssv31.get("confidentialityImpact"),
                integrityImpact_v31=vulnerability.cvssv31.get("integrityImpact"),
                availabilityImpact_v31=vulnerability.cvssv31.get("availabilityImpact"),
                baseScore_v31=vulnerability.cvssv31.get("baseScore"),
                baseSeverity_v31=vulnerability.cvssv31.get("baseSeverity"),
                exploitabilityScore_v31=vulnerability.cvssv31.get("exploitabilityScore"),
                impactScore_v31=vulnerability.cvssv31.get("impactScore"),
                vectorString_v40=vulnerability.cvssv40.get("vectorString"),
                attackVector_v40=vulnerability.cvssv40.get("attackVector"),
                attackComplexity_v40=vulnerability.cvssv40.get("attackComplexity"),
                attackRequirements_v40=vulnerability.cvssv40.get("attackRequirements"),
                privilegesRequired_v40=vulnerability.cvssv40.get("privilegesRequired"),
                userInteraction_v40=vulnerability.cvssv40.get("userInteraction"),
                vulnerableSystemConfidentiality_v40=vulnerability.cvssv40.get("vulnerableSystemConfidentiality"),
                vulnerableSystemIntegrity_v40=vulnerability.cvssv40.get("vulnerableSystemIntegrity"),
                vulnerableSystemAvailability_v40=vulnerability.cvssv40.get("vulnerableSystemAvailability"),
                subsequentSystemConfidentiality_v40=vulnerability.cvssv40.get("subsequentSystemConfidentiality"),
                subsequentSystemIntegrity_v40=vulnerability.cvssv40.get("subsequentSystemIntegrity"),
                subsequentSystemAvailability_v40=vulnerability.cvssv40.get("subsequentSystemAvailability"),
                baseScore_v40=vulnerability.cvssv40.get("baseScore"),
                baseSeverity_v40=vulnerability.cvssv40.get("baseSeverity"),
                cpe_type=list(vulnerability.cpe_type),
                ref_tags=list(vulnerability.ref_tag),
                published=vulnerability.published,
                lastModified=vulnerability.lastModified,
                result_impacts=vulnerability.result_impacts
            )
            client.create_relationship_between_cve_and_vulnerability(vulnerability.cve, vul_description)
            cve_count_updated += 1
    logging.info(f"Created {cve_count_created} CVEs, updated {cve_count_updated} CVEs")


def parse_cpe(full_cpe: str) -> Tuple[str, str, str]:
    """
    Parses a CPE string into vendor, product, and version components.

    :param full_cpe: CPE string (e.g., 'cpe:2.3:a:vendor:product:version:...').
    :return: Tuple of (vendor, product, version).
    :raises ValueError: If CPE string is malformed.
    """
    try:
        cpe_parts = full_cpe.split(':')
        if len(cpe_parts) < 6:
            raise ValueError(f"Malformed CPE string: {full_cpe}")
        return cpe_parts[3], cpe_parts[4], cpe_parts[5]
    except (IndexError, ValueError) as e:
        logging.error(f"Failed to parse CPE {full_cpe}: {e}")
        raise ValueError(f"Invalid CPE format: {full_cpe}")


def check_ranges(cpe_match: Dict[str, Any], version: str, nvd_api_key: str) -> bool:
    """
    Checks if a software version falls within the specified version range.

    Uses semantic versioning for comparison if possible, falling back to string comparison.

    :param cpe_match: Dictionary with version range keys (e.g., 'versionStartIncluding').
    :param version: Software version to check.
    :return: True if version is within range; False otherwise.
    """
    logging.info(f"Checking CPE range: {cpe_match}")
    if parse_cpe(cpe_match["criteria"])[2] != "*":
        raise ValueError(f"Invalid CPE range containing version number: {cpe_match}")

    # if version.count('.') > 1:
    #     match = re.match(r"(?P<major>.*?)\.(?P<minor>.*?)\.(?P<build>.*)", version)
    #     shortened_cpe = vendor + ":" + product + ":" + match.group(1) + "." + match.group(2)

    if "versionStartIncluding" in cpe_match or "versionStartExcluding" in cpe_match or \
            "versionEndIncluding" in cpe_match or "versionEndExcluding" in cpe_match:
        result = False
        current_version = Version(version)
        if "versionStartIncluding" in cpe_match:
            condition = Version(cpe_match['versionStartIncluding'])
            if current_version < condition:
                return False
            result = True
        if "versionStartExcluding" in cpe_match:
            condition = Version(cpe_match['versionStartExcluding'])
            if current_version <= condition:
                return False
            result = True
        if "versionEndIncluding" in cpe_match:
            condition = Version(cpe_match['versionEndIncluding'])
            if current_version > condition:
                return False
            result = True
        if "versionEndExcluding" in cpe_match:
            condition = Version(cpe_match['versionEndExcluding'])
            if current_version >= condition:
                return False
            result = True
        logging.info(f"Successful check CPE range: {cpe_match}")
        return result

    else:
        # CPE has * (ANY) as a version, but does not have any indication of start and end - matchCriteriaId should be used
        url = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
        params = {'matchCriteriaId': f"{cpe_match['matchCriteriaId']}"}
        headers = {'apiKey': api_key} if nvd_api_key else {}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            for match_string in data["matchStrings"]:
                for match in match_string["matchString"]["matches"]:
                    if parse_cpe(match["cpeName"])[2] == version:
                        logging.info(f"Successful check of CPE range: {cpe_match} and version: {match['cpeName']}")
                        return True
        return False


def check_configurations(client: CVEConnectorClient, cpe_configurations: List[Dict[str, Any]],
                         vul_description: str, flag: bool, nvd_api_key: str) -> bool:
    """
    Processes CPE configurations to determine if a vulnerability node should be created or updated.

    Handles 'AND' and 'OR' operators in configurations, processing CPE matches to create relationships.

    :param client: CVEConnectorClient for Neo4j interactions.
    :param cpe_configurations: Configuration data for the vulnerability.
    :param vul_description: Vulnerability description.
    :param flag: Indicates if a vulnerability node was created.
    :return: Updated flag indicating if a vulnerability node was created.
    :raises ValueError: If configuration structure is invalid.
    """
    vulnerability_created = flag
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
                        if cpe_item.get("vulnerable"):
                            vulnerability_created = process_nvd_cpe(client, cpe_item, vul_description,
                                                                    vulnerability_created, nvd_api_key)
                else:
                    logging.warning(f"Expected two nodes in AND configuration, got {len(configuration.get('nodes', []))}")
        else:
            for node in configuration.get("nodes", []):
                if node.get("operator", "") == "OR":
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            vulnerability_created = process_nvd_cpe(client, cpe_match, vul_description,
                                                                    vulnerability_created, nvd_api_key)
    return vulnerability_created


def process_nvd_cpe(client: CVEConnectorClient, cpe_match: Dict[str, Any], vul_description: str, flag: bool, nvd_api_key) -> bool:
    """
    Processes a CPE match to create relationships between vulnerabilities and software versions.

    :param client: CVEConnectorClient for Neo4j interactions.
    :param cpe_match: CPE match data with criteria and version ranges.
    :param vul_description: Vulnerability description.
    :param flag: Indicates if a vulnerability node was created.
    :return: Updated flag indicating if a vulnerability node was created.
    """
    vulnerability_created = flag
    try:
        vendor, product, version = parse_cpe(cpe_match["criteria"])
        logging.info(f"{vul_description} Processing CPE match for vendor={vendor}, product={product}, version={version}")
        if version.count('.') > 1:
            match = re.match(r"(?P<major>.*?)\.(?P<minor>.*?)\.(?P<build>.*)", version)
            shortened_cpe = vendor + ":" + product + ":" + match.group(1) + "." + match.group(2)
            if client.software_version_exists(shortened_cpe):
                if not vulnerability_created:
                    vulnerability_created = True
                    client.create_new_vulnerability(vul_description)
                client.create_relationship_between_vulnerability_and_software_version(
                    vul_description, shortened_cpe
                )
        for possible_software_version in [vendor + ":" + product + ":" + version,
                                        vendor + ":" + product + ":*",
                                        vendor + ":*:*"]:
            if client.software_version_exists(possible_software_version):
                if not vulnerability_created:
                    vulnerability_created = True
                    client.create_new_vulnerability(vul_description)
                client.create_relationship_between_vulnerability_and_software_version(
                    vul_description, possible_software_version)

        # Other parts of code should be executed only for ANY (*) version
        if parse_cpe(cpe_match["criteria"])[2] != "*":
            return vulnerability_created

        # vendor_and_product = vendor + ":" + product + ":*"
        vendor_and_product = vendor + ":" + product
        # logging.info(f"Before get versions for vendor={vendor}, product={product}, version={version}")
        sw_versions = [v["software"]["version"] for v in client.get_versions_of_product(vendor_and_product)]
        # logging.info(f"After get versions, obtained {sw_versions}")
        # for sw_version in client.get_versions_of_product(vendor_and_product):
        for sw_version in sw_versions:
            # logging.info(f"Inside of for loop for vendor={vendor}, product={product}, version={sw_version}")
            possible_version = sw_version[sw_version.rfind(':') + 1:]
            if check_ranges(cpe_match, possible_version, nvd_api_key):
                if not vulnerability_created:
                    vulnerability_created = True
                    client.create_new_vulnerability(vul_description)
                client.create_relationship_between_vulnerability_and_software_version(
                    vul_description, vendor + ":" + product + ":" + possible_version)
    except Exception as e:
        logging.warning(f"Skipping CPE processing due to error: {e}")
    
    return vulnerability_created


def get_software_versions_from_neo4j(neo4j_passwd: str, bolt: str = "bolt://localhost:7687", user: str = "neo4j") -> List[str]:
    """
    Retrieves all software versions stored in the Neo4j database.

    :param neo4j_passwd: Password for Neo4j authentication.
    :param bolt: Bolt connection string. Defaults to "bolt://localhost:7687".
    :param user: Username for Neo4j. Defaults to "neo4j".
    :return: List of software version strings.
    """
    client = CVEConnectorClient(password=neo4j_passwd, bolt=bolt, user=user)
    return client.get_all_software_versions()
