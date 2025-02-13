"""Module."""

import re
import logging
from typing import List, Tuple
from cve_connector.nvd_cve.CveConnectorClient import CVEConnectorClient
from cve_connector.nvd_cve.vulnerability import Vulnerability


def move_cve_data_to_neo4j(vulnerability_list: List[Vulnerability], neo4j_bolt, neo4j_passwd):
    client = CVEConnectorClient(bolt=neo4j_bolt, password=neo4j_passwd)
    cve_count_created = 0
    cve_count_updated = 0
    for vulnerability in vulnerability_list:
        vul_description = "Assumed vulnerability with ID " + vulnerability.cve
        if not client.cve_exists(vulnerability.cve):
            vulnerability_created = check_configurations(
                client, vulnerability.cpe_configurations,
                vul_description, False)
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
                                    vul_description, True)
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
            cve_count_updated += 1
    logging.info(str(cve_count_created) + " | " + str(cve_count_updated))


def parse_cpe(full_cpe) -> Tuple:
    cpe_parts = full_cpe.split(':')
    vendor = cpe_parts[3]
    product = cpe_parts[4]
    version = cpe_parts[5]
    return vendor, product, version


def check_ranges(cpe_match, version) -> bool:
    if "versionStartIncluding" in cpe_match and version < cpe_match['versionStartIncluding']:
        return False
    if "versionStartExcluding" in cpe_match and version <= cpe_match['versionStartExcluding']:
        return False
    if "versionEndIncluding" in cpe_match and version > cpe_match["versionEndIncluding"]:
        return False
    if "versionEndExcluding" in cpe_match and version >= cpe_match["versionEndExcluding"]:
        return False
    return True


def check_configurations(client: CVEConnectorClient, cpe_configurations, vul_description, flag):
    vulnerability_created = flag
    for configuration in cpe_configurations:
        if "operator" in configuration:
            if configuration["operator"] == "AND":
                if len(configuration["nodes"]) == 2:
                    if configuration["nodes"][0]["cpeMatch"][0]["vulnerable"]:
                        vulnerable_dict = configuration["nodes"][0]
                        non_vulnerable_dict = configuration["nodes"][1]
                    else:
                        vulnerable_dict = configuration["nodes"][1]
                        non_vulnerable_dict = configuration["nodes"][0]
                    if vulnerable_dict["operator"] != "OR" or non_vulnerable_dict["operator"] != "OR":
                        raise ValueError("Depth of recursion was more than 1.")
                    for cpe_item in vulnerable_dict["cpeMatch"]:
                        if cpe_item["vulnerable"]:
                            vulnerability_created = process_nvd_cpe(client, cpe_item, 
                                                                    vul_description,
                                                                    vulnerability_created)
                else:
                    logging.warning(f"Not two children in AND configuration {configuration}")
        else:
            if "nodes" in configuration:
                for node in configuration["nodes"]:
                    if "operator" in node:
                        if node["operator"] == "OR":
                            if "cpeMatch" in node:
                                for cpe_match in node["cpeMatch"]:
                                    if cpe_match["vulnerable"]:
                                        vulnerability_created = process_nvd_cpe(client, cpe_match, 
                                                                                vul_description,
                                                                                vulnerability_created)
                            else:
                                logging.warning(f"This OR configuration does not contain key 'cpe_match': {node}")
    return vulnerability_created


def process_nvd_cpe(client: CVEConnectorClient, cpe_match, vul_description, flag):
    vulnerability_created = flag
    vendor, product, version = parse_cpe(cpe_match["criteria"])
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

    vendor_and_product = vendor + ":" + product + ":*"
    for sw_version in client.get_versions_of_product(vendor_and_product):
        possible_version = sw_version[sw_version.rfind(':') + 1:]
        if check_ranges(cpe_match, possible_version):
            if not vulnerability_created:
                vulnerability_created = True
                client.create_new_vulnerability(vul_description)
            client.create_relationship_between_vulnerability_and_software_version(
                vul_description, vendor + ":" + product + ":" + possible_version)
    return vulnerability_created
