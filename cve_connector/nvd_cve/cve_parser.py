"""
Module for Parsing Raw Vulnerability Data into Vulnerability Objects

This module provides a function to parse a list of dictionaries (typically obtained from a CVE
data source such as the NVD API) into a list of Vulnerability objects. The parsing process involves
extracting key information including the CVE identifier, description, weaknesses (CWE), various CVSS
metrics (v2, v3.0, v3.1, v4.0), configurations (CPE types), publication dates, modification dates,
and reference tags. It also utilizes the classifier function to compute the impact(s) associated with
each vulnerability. The resulting Vulnerability objects are then used as part of a larger vulnerability
analysis and classification framework.
"""

import logging
from typing import Any

from cve_connector.nvd_cve.categorization.classifier import classifier
from cve_connector.nvd_cve.vulnerability import Vulnerability


def parse_vulnerabilities(data: list[dict[str, Any]]) -> list[Vulnerability]:
    """
    Parses a list of raw vulnerability data dictionaries into a list of Vulnerability objects.

    For each dictionary in the provided data list, this function:
      - Creates a new Vulnerability object.
      - Extracts the CVE identifier and description.
      - Gathers weaknesses (CWE values) from the 'weaknesses' field.
      - Parses CVSS metrics for versions 2, 3.0, 3.1, and 4.0 from the 'metrics' field and updates
        the corresponding attributes in the Vulnerability object, prioritizing primary metrics.
      - Processes configuration data to determine CPE types and stores the full configurations.
      - Extracts publication and last modification dates.
      - Aggregates reference tags from the 'references' field.
      - Calls the classifier function to compute and assign the result impacts.

    The function returns a list of fully populated Vulnerability objects.

    Parameters:
      data (List[Dict[str, Any]]): A list of dictionaries, where each dictionary contains raw vulnerability
                                   information as provided by a CVE data source.

    Returns:
      List[Vulnerability]: A list of Vulnerability objects populated with the parsed data.
    """
    vulnerabilities: list[Vulnerability] = []
    for item in data:
        vulnerability = Vulnerability()
        if not item.get("id") or not item.get("descriptions"):
            logging.warning(f"Skipping CVE with missing id or descriptions: {item}")
            continue
        vulnerability.cve = item["id"]
        vulnerability.description = item["descriptions"][0].get("value", "")

        if "weaknesses" in item:
            for weakness in item.get("weaknesses", []):
                for description in weakness.get("description", []):
                    vulnerability.cwe.add(description.get("value", ""))

        def get_primary_metric(metric_list: list[dict[str, Any]]) -> dict[str, Any] | None:
            for metric in metric_list:
                if metric.get("type") == "Primary":
                    return metric
            return metric_list[0] if metric_list else None

        if "cvssMetricV2" in item.get("metrics", {}):
            tmp = get_primary_metric(item["metrics"]["cvssMetricV2"])
            if tmp:
                vulnerability.cvssv2.update(
                    {
                        "vectorString": tmp["cvssData"]["vectorString"],
                        "accessVector": tmp["cvssData"]["accessVector"],
                        "accessComplexity": tmp["cvssData"]["accessComplexity"],
                        "authentication": tmp["cvssData"]["authentication"],
                        "confidentialityImpact": tmp["cvssData"]["confidentialityImpact"],
                        "integrityImpact": tmp["cvssData"]["integrityImpact"],
                        "availabilityImpact": tmp["cvssData"]["availabilityImpact"],
                        "baseScore": tmp["cvssData"]["baseScore"],
                        "baseSeverity": tmp["baseSeverity"],
                        "exploitabilityScore": tmp["exploitabilityScore"],
                        "impactScore": tmp["impactScore"],
                        "acInsufInfo": tmp.get("acInsufInfo"),
                        "obtainAllPrivilege": tmp.get("obtainAllPrivilege"),
                        "obtainUserPrivilege": tmp.get("obtainUserPrivilege"),
                        "obtainOtherPrivilege": tmp.get("obtainOtherPrivilege"),
                        "userInteractionRequired": tmp.get("userInteractionRequired"),
                    }
                )
        if "cvssMetricV30" in item.get("metrics", {}):
            tmp = get_primary_metric(item["metrics"]["cvssMetricV30"])
            if tmp:
                vulnerability.cvssv30.update(
                    {
                        "vectorString": tmp["cvssData"]["vectorString"],
                        "attackVector": tmp["cvssData"]["attackVector"],
                        "attackComplexity": tmp["cvssData"]["attackComplexity"],
                        "privilegesRequired": tmp["cvssData"]["privilegesRequired"],
                        "userInteraction": tmp["cvssData"]["userInteraction"],
                        "scope": tmp["cvssData"]["scope"],
                        "confidentialityImpact": tmp["cvssData"]["confidentialityImpact"],
                        "integrityImpact": tmp["cvssData"]["integrityImpact"],
                        "availabilityImpact": tmp["cvssData"]["availabilityImpact"],
                        "baseScore": tmp["cvssData"]["baseScore"],
                        "baseSeverity": tmp["cvssData"]["baseSeverity"],
                        "exploitabilityScore": tmp["exploitabilityScore"],
                        "impactScore": tmp["impactScore"],
                    }
                )
        if "cvssMetricV31" in item.get("metrics", {}):
            tmp = get_primary_metric(item["metrics"]["cvssMetricV31"])
            if tmp:
                vulnerability.cvssv31.update(
                    {
                        "vectorString": tmp["cvssData"]["vectorString"],
                        "attackVector": tmp["cvssData"]["attackVector"],
                        "attackComplexity": tmp["cvssData"]["attackComplexity"],
                        "privilegesRequired": tmp["cvssData"]["privilegesRequired"],
                        "userInteraction": tmp["cvssData"]["userInteraction"],
                        "scope": tmp["cvssData"]["scope"],
                        "confidentialityImpact": tmp["cvssData"]["confidentialityImpact"],
                        "integrityImpact": tmp["cvssData"]["integrityImpact"],
                        "availabilityImpact": tmp["cvssData"]["availabilityImpact"],
                        "baseScore": tmp["cvssData"]["baseScore"],
                        "baseSeverity": tmp["cvssData"]["baseSeverity"],
                        "exploitabilityScore": tmp["exploitabilityScore"],
                        "impactScore": tmp["impactScore"],
                    }
                )
        if "cvssMetricV40" in item.get("metrics", {}):
            tmp = get_primary_metric(item["metrics"]["cvssMetricV40"])
            if tmp:
                vulnerability.cvssv40.update(
                    {
                        "vectorString": tmp["cvssData"]["vectorString"],
                        "attackVector": tmp["cvssData"]["attackVector"],
                        "attackComplexity": tmp["cvssData"]["attackComplexity"],
                        "attackRequirements": tmp["cvssData"]["attackRequirements"],
                        "privilegesRequired": tmp["cvssData"]["privilegesRequired"],
                        "userInteraction": tmp["cvssData"]["userInteraction"],
                        "vulnerableSystemConfidentiality": tmp["cvssData"]["vulnConfidentialityImpact"],
                        "vulnerableSystemIntegrity": tmp["cvssData"]["vulnIntegrityImpact"],
                        "vulnerableSystemAvailability": tmp["cvssData"]["vulnAvailabilityImpact"],
                        "subsequentSystemConfidentiality": tmp["cvssData"]["subConfidentialityImpact"],
                        "subsequentSystemIntegrity": tmp["cvssData"]["subIntegrityImpact"],
                        "subsequentSystemAvailability": tmp["cvssData"]["subAvailabilityImpact"],
                        "exploitMaturity": tmp["cvssData"]["exploitMaturity"],
                        "baseScore": tmp["cvssData"]["baseScore"],
                        "baseSeverity": tmp["cvssData"]["baseSeverity"],
                    }
                )

        if "configurations" in item:
            for cpe_item in item.get("configurations", []):
                for node in cpe_item.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        if cpe.get("vulnerable"):
                            criteria = cpe.get("criteria", "")
                            if criteria:
                                vulnerability.cpe_type.add(criteria.split(":")[2])
            vulnerability.cpe_configurations = item["configurations"]

        vulnerability.published = item.get("published", "")
        vulnerability.lastModified = item.get("lastModified", "")

        for ref in item.get("references", []):
            for tag in ref.get("tags", []):
                vulnerability.ref_tag.add(tag)

        vulnerability.result_impacts = list(set(classifier(vulnerability)))
        vulnerabilities.append(vulnerability)

    return vulnerabilities
