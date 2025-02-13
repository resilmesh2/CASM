from typing import List, Dict, Set, Any


from cve_connector.nvd_cve.categorization.classifier import classifier
from cve_connector.nvd_cve.vulnerability import Vulnerability


def parse_vulnerabilities(data: List[Dict[str, Any]]) -> List[Vulnerability]:
    vulnerabilities: List[Vulnerability] = []
    for item in data:
        vulnerability = Vulnerability()
        vulnerability.cve = item["id"]
        vulnerability.description = item["descriptions"][0]["value"]
        if "weaknesses" in item:
            for weakness in item["weaknesses"]:
                for description in weakness["description"]:
                    vulnerability.cwe.add(description["value"])
        if "cvssMetricV2" in item["metrics"]:
            tmp: Dict[str, Any] = item["metrics"]["cvssMetricV2"][0]
            vulnerability.cvssv2.update({
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
            })
        if "cvssMetricV30" in item["metrics"]:
            tmp: Dict[str, Any] = item["metrics"]["cvssMetricV30"][0]
            vulnerability.cvssv30.update({
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
            })
        if "cvssMetricV31" in item["metrics"]:
            tmp: Dict[str, Any] = item["metrics"]["cvssMetricV31"][0]
            vulnerability.cvssv31.update({
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
            })
        if "cvssMetricV40" in item["metrics"]:
            tmp: Dict[str, Any] = item["metrics"]["cvssMetricV40"][0]
            vulnerability.cvssv40.update({
                "vectorString": tmp["cvssData"]["vectorString"],
                "attackVector": tmp["cvssData"]["attackVector"],
                "attackComplexity": tmp["cvssData"]["attackComplexity"],
                "attackRequirements": tmp["cvssData"]["attackRequirements"],
                "privilegesRequired": tmp["cvssData"]["privilegesRequired"],
                "userInteraction": tmp["cvssData"]["userInteraction"],
                "vulnerableSystemConfidentiality": tmp["cvssData"]["vulnerableSystemConfidentiality"],
                "vulnerableSystemIntegrity": tmp["cvssData"]["vulnerableSystemIntegrity"],
                "vulnerableSystemAvailability": tmp["cvssData"]["vulnerableSystemAvailability"],
                "subsequentSystemConfidentiality": tmp["cvssData"]["subsequentSystemConfidentiality"],
                "subsequentSystemIntegrity": tmp["cvssData"]["subsequentSystemIntegrity"],
                "subsequentSystemAvailability": tmp["cvssData"]["subsequentSystemAvailability"],
                "baseScore": tmp["cvssData"]["baseScore"],
                "baseSeverity": tmp["cvssData"]["baseSeverity"],
            })
        if "configurations" in item:
            for cpe_item in item["configurations"]:
                if "nodes" in cpe_item:
                    for node in cpe_item["nodes"]:
                        if "cpeMatch" in node:
                            for cpe in node["cpeMatch"]:
                                if cpe["vulnerable"]:
                                    vulnerability.cpe_type.add(cpe["criteria"].split(':')[2])
            vulnerability.cpe_configurations = item["configurations"]
        vulnerability.published = item["published"]
        vulnerability.lastModified = item["lastModified"]
        if "references" in item:
            for ref in item["references"]:
                if "tags" in ref:
                    for tag in ref["tags"]:
                        vulnerability.ref_tag.add(tag)
        vulnerability.result_impacts = list(set(classifier(vulnerability)))
        vulnerabilities.append(vulnerability)
    return vulnerabilities
