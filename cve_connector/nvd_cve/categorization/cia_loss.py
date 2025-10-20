"""
Module for Assessing CIA Loss and Changes in System Vulnerabilities

This module provides functions to determine whether a vulnerability causes a loss
of system confidentiality, integrity, or availability (CIA). It also evaluates whether
there has been a change in these metrics compared to the initial vulnerable state.
The analysis is based on a combination of CVSS metrics from different versions (v4.0, v3.1,
v3.0, and v2) and textual analysis of the vulnerability description. These functions are
designed to be used as part of a larger vulnerability classification framework.

Functions:
  - has_system_confidentiality_loss: Checks if the vulnerability leads to a loss of confidentiality.
  - has_system_integrity_loss: Determines if the vulnerability compromises system integrity.
  - has_system_availability_loss: Evaluates if the vulnerability causes system availability loss.
  - system_confidentiality_changed: Assesses whether the confidentiality metric has changed.
  - system_integrity_changed: Assesses whether the integrity metric has changed.
  - system_availability_changed: Assesses whether the availability metric has changed.
  - add_other_cia_impacts: Supplements a set of detected CIA impacts with any missing impacts based on CVSS metrics.

Dependencies:
  - test_incidence, cve_is_about_system from cve_connector.nvd_cve.categorization.utils.
  - Vulnerability from cve_connector.nvd_cve.vulnerability.
"""

from cve_connector.nvd_cve.categorization.utils import cve_is_about_system, test_incidence
from cve_connector.nvd_cve.vulnerability import Vulnerability


def has_system_confidentiality_loss(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the given vulnerability results in a loss of system confidentiality.

    This function evaluates if the vulnerability causes confidentiality loss by:
      - Verifying that the vulnerability targets a system (using its CPE type).
      - Examining CVSS metrics from versions 4.0, 3.1, 3.0, and 2.
      - Scanning the vulnerability description for sufficient textual indicators (from a predefined list)
        that suggest confidentiality is compromised.

    Evaluation details:
      - For CVSS v4.0: If "vulnerableSystemConfidentiality" is LOW, the description is scanned for
        sufficient indicators; otherwise, a HIGH value indicates confidentiality loss.
      - For CVSS v3.1 and v3.0: Similar logic is applied using the "confidentialityImpact" metric.
      - For CVSS v2: If "confidentialityImpact" is PARTIAL, the sufficient condition phrases are checked;
        otherwise, a COMPLETE value is required to indicate loss.

    :param vulnerability: An instance of Vulnerability containing CVSS metrics, description, and CPE type.
    :return: True if the vulnerability causes system confidentiality loss; otherwise, False.
    """
    sufficient_condition: list[str] = [
        "devices allow remote attackers to read arbitrary files",
        "compromise the systems confidentiality",
        "read any file on the camera's linux filesystem",
        "gain read-write access to system settings",
        "all system settings can be read",
        "leak information about any clients connected to it",
        "read sensitive files on the system",
        "access arbitrary files on an affected device",
        "access system files",
        "gain unauthorized read access to files on the host",
        "obtain sensitive system information",
        "obtain sensitive information from kernel memory",
        "obtain privileged file system access",
        "routers allow directory traversal sequences",
        "packets can contain fragments of system memory",
        "obtain kernel memory",
        "read kernel memory",
        "read system memory",
        "reading system memory",
        "read device memory",
        "read host memory",
        "access kernel memory",
        "access sensitive kernel memory",
        "access shared memory",
        "host arbitrary files",
        "enumerate user accounts",
        "compromise an affected system",
    ]
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    if len(vulnerability.cvssv40.keys()) != 0:
        if vulnerability.cvssv40.get("vulnerableSystemConfidentiality", "") == "LOW" and test_incidence(
            vulnerability.description, sufficient_condition
        ):
            return True
        return vulnerability.cvssv40.get("vulnerableSystemConfidentiality", "") == "HIGH"
    if len(vulnerability.cvssv31.keys()) != 0:
        if vulnerability.cvssv31.get("confidentialityImpact", "") == "LOW" and test_incidence(
            vulnerability.description, sufficient_condition
        ):
            return True
        return vulnerability.cvssv31.get("confidentialityImpact", "") == "HIGH"
    if len(vulnerability.cvssv30.keys()) != 0:
        if vulnerability.cvssv30.get("confidentialityImpact", "") == "LOW" and test_incidence(
            vulnerability.description, sufficient_condition
        ):
            return True
        return vulnerability.cvssv30.get("confidentialityImpact", "") == "HIGH"
    if vulnerability.cvssv2.get("confidentialityImpact", "") == "PARTIAL" and test_incidence(
        vulnerability.description, sufficient_condition
    ):
        return True
    return vulnerability.cvssv2.get("confidentialityImpact", "") == "COMPLETE"


def has_system_integrity_loss(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the given vulnerability results in a loss of system integrity.

    The function checks if the vulnerability compromises system integrity by:
      - Ensuring the vulnerability targets a system.
      - Evaluating CVSS metrics (v4.0, v3.1, v3.0, and v2) for integrity loss.
      - Scanning the description for phrases (from a predefined list) that indicate modification
        of system files, settings, or kernel memory.

    Evaluation details:
      - For CVSS v4.0: If "vulnerableSystemIntegrity" is LOW, the description is checked for sufficient indicators; otherwise, HIGH indicates loss.
      - For CVSS v3.1 and v3.0: Similar evaluation using "integrityImpact".
      - For CVSS v2: If "integrityImpact" is PARTIAL and sufficient phrases are present, returns True; otherwise, COMPLETE is required.

    :param vulnerability: An instance of Vulnerability containing CVSS metrics, description, and CPE type.
    :return: True if the vulnerability causes system integrity loss; otherwise, False.
    """
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    sufficient_condition: list[str] = [
        "compromise the systems confidentiality or integrity",
        "gain read-write access to system settings",
        "all system settings can be read and changed",
        "create arbitrary directories on the affected system",
        "on ismartalarm cube devices, there is incorrect access control",
        "bypass url filters that have been configured for an affected device",
        "bypass configured filters on the device",
        "modification of system files",
        "obtain privileged file system access",
        "change configuration settings",
        "compromise the affected system",
        "overwrite arbitrary kernel memory",
        "modify kernel memory",
        "overwrite kernel memory",
        "modifying kernel memory",
        "overwriting kernel memory",
        "corrupt kernel memory",
        "corrupt user memory",
        "upload firmware changes",
        "configuration parameter changes",
        "obtain sensitive information from kernel memory",
        "change the device's settings",
        "configuration changes",
        "modification of system states",
        "host arbitrary files",
    ]
    if len(vulnerability.cvssv40.keys()) != 0:
        if vulnerability.cvssv40.get("vulnerableSystemIntegrity", "") == "LOW" and test_incidence(
            vulnerability.description, sufficient_condition
        ):
            return True
        return vulnerability.cvssv40.get("vulnerableSystemIntegrity", "") == "HIGH"
    if len(vulnerability.cvssv31.keys()) != 0:
        if vulnerability.cvssv31.get("integrityImpact", "") == "LOW" and test_incidence(
            vulnerability.description, sufficient_condition
        ):
            return True
        return vulnerability.cvssv31.get("integrityImpact", "") == "HIGH"
    if len(vulnerability.cvssv30.keys()) != 0:
        if vulnerability.cvssv30.get("integrityImpact", "") == "LOW" and test_incidence(
            vulnerability.description, sufficient_condition
        ):
            return True
        return vulnerability.cvssv30.get("integrityImpact", "") == "HIGH"
    if vulnerability.cvssv2.get("integrityImpact", "") == "PARTIAL" and test_incidence(
        vulnerability.description, sufficient_condition
    ):
        return True
    return vulnerability.cvssv2.get("integrityImpact", "") == "COMPLETE"


def has_system_availability_loss(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the given vulnerability results in a loss of system availability.

    This function assesses system availability loss by:
      - Checking the vulnerability description for tokens (e.g., 'device crash', 'system crash') that
        imply a denial-of-service or similar effect.
      - Evaluating CVSS metrics (v4.0, v3.1, v3.0, and v2) for availability impact.
      - Using a sufficient_condition list to scan the description when the CVSS metric is LOW.
      - Considering any non-NONE availability impact as significant when system integrity loss is present.

    :param vulnerability: An instance of Vulnerability containing CVSS metrics, description, and CPE type.
    :return: True if the vulnerability causes system availability loss; otherwise, False.
    """
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    system_tokens: list[str] = ["device crash", "device reload", "system crash", "cpu consumption"]
    for token in system_tokens:
        if token in vulnerability.description:
            return True
    sufficient_condition: list[str] = [
        "an extended denial of service condition for the device",
        "exhaust the memory resources of the machine",
        "denial of service (dos) condition on an affected device",
        "crash systemui",
        "denial of service (dos) condition on the affected appliance",
        "cause the device to hang or unexpectedly reload",
        "denial of service (use-after-free) via a crafted application",
        "cause an affected device to reload",
        "cause an affected system to stop",
    ]
    if len(vulnerability.cvssv40.keys()) != 0:
        if vulnerability.cvssv40.get("vulnerableSystemAvailability", "") == "LOW" and test_incidence(
            vulnerability.description, sufficient_condition
        ):
            return True
        if has_system_integrity_loss(vulnerability):
            return vulnerability.cvssv40.get("vulnerableSystemAvailability", "") != "NONE"
        return vulnerability.cvssv40.get("vulnerableSystemAvailability", "") == "HIGH"
    if len(vulnerability.cvssv31.keys()) != 0:
        if vulnerability.cvssv31.get("availabilityImpact", "") == "LOW" and test_incidence(
            vulnerability.description, sufficient_condition
        ):
            return True
        if has_system_integrity_loss(vulnerability):
            return vulnerability.cvssv31.get("availabilityImpact", "") != "NONE"
        return vulnerability.cvssv31.get("availabilityImpact", "") == "HIGH"
    if len(vulnerability.cvssv30.keys()) != 0:
        if vulnerability.cvssv30.get("availabilityImpact", "") == "LOW" and test_incidence(
            vulnerability.description, sufficient_condition
        ):
            return True
        if has_system_integrity_loss(vulnerability):
            return vulnerability.cvssv30.get("availabilityImpact", "") != "NONE"
        return vulnerability.cvssv30.get("availabilityImpact", "") == "HIGH"
    if vulnerability.cvssv2.get("availabilityImpact", "") == "PARTIAL" and test_incidence(
        vulnerability.description, sufficient_condition
    ):
        return True
    if has_system_integrity_loss(vulnerability):
        return vulnerability.cvssv2.get("availabilityImpact", "") != "NONE"
    return vulnerability.cvssv2.get("availabilityImpact", "") == "COMPLETE"


def system_confidentiality_changed(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the vulnerability indicates a change in system confidentiality.

    This function checks if the confidentiality level has changed from its initial vulnerable state:
      - For CVSS v4.0, it compares "subsequentSystemConfidentiality" with "vulnerableSystemConfidentiality".
      - For CVSS v3.1 and v3.0, a change is indicated by a "CHANGED" scope.
      - For CVSS v2, if the description mentions "in the remote system" and the confidentiality impact is PARTIAL,
        the function returns True.

    :param vulnerability: An instance of Vulnerability containing CVSS metrics, description, and CPE type.
    :return: True if system confidentiality is changed; otherwise, False.
    """
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    if len(vulnerability.cvssv40.keys()) != 0:
        if (
            "in the remote system" in vulnerability.description
            and vulnerability.cvssv40["vulnerableSystemConfidentiality"] == "HIGH"
        ):
            return True
        if (
            cve_is_about_system(vulnerability.cpe_type)
            and vulnerability.cvssv40["vulnerableSystemConfidentiality"] == "HIGH"
        ):
            return True
    if len(vulnerability.cvssv31.keys()) != 0:
        if (
            "in the remote system" in vulnerability.description
            and vulnerability.cvssv31.get("confidentialityImpact", "") == "HIGH"
        ):
            return True
        if (
            cve_is_about_system(vulnerability.cpe_type)
            and vulnerability.cvssv31.get("confidentialityImpact", "") == "HIGH"
        ):
            return True
    if len(vulnerability.cvssv30.keys()) != 0:
        if (
            "in the remote system" in vulnerability.description
            and vulnerability.cvssv30.get("confidentialityImpact", "") == "HIGH"
        ):
            return True
        if (
            cve_is_about_system(vulnerability.cpe_type)
            and vulnerability.cvssv30.get("confidentialityImpact", "") == "HIGH"
        ):
            return True
    if (
        "in the remote system" in vulnerability.description
        and vulnerability.cvssv2.get("confidentialityImpact", "") == "PARTIAL"
    ):
        return True
    return (
        cve_is_about_system(vulnerability.cpe_type)
        and vulnerability.cvssv2.get("confidentialityImpact", "") == "PARTIAL"
    )


def system_integrity_changed(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the vulnerability indicates a change in system integrity.

    The function checks if the integrity level has shifted from its vulnerable state:
      - For CVSS v4.0, it compares "subsequentSystemIntegrity" with "vulnerableSystemIntegrity".
      - For CVSS v3.1 and v3.0, a "CHANGED" scope indicates a modification.
      - For CVSS v2, if the description includes "in the remote system" and the integrity impact is PARTIAL,
        it returns True.

    :param vulnerability: An instance of Vulnerability with CVSS metrics, description, and CPE type.
    :return: True if system integrity is changed; otherwise, False.
    """
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    if len(vulnerability.cvssv40.keys()) != 0:
        if (
            "in the remote system" in vulnerability.description
            and vulnerability.cvssv40["vulnerableSystemIntegrity"] == "HIGH"
        ):
            return True
        if cve_is_about_system(vulnerability.cpe_type) and vulnerability.cvssv40["vulnerableSystemIntegrity"] == "HIGH":
            return True
    if len(vulnerability.cvssv31.keys()) != 0:
        if (
            "in the remote system" in vulnerability.description
            and vulnerability.cvssv31.get("integrityImpact", "") == "HIGH"
        ):
            return True
        if cve_is_about_system(vulnerability.cpe_type) and vulnerability.cvssv31.get("integrityImpact", "") == "HIGH":
            return True
    if len(vulnerability.cvssv30.keys()) != 0:
        if (
            "in the remote system" in vulnerability.description
            and vulnerability.cvssv30.get("integrityImpact", "") == "HIGH"
        ):
            return True
        if cve_is_about_system(vulnerability.cpe_type) and vulnerability.cvssv30.get("integrityImpact", "") == "HIGH":
            return True
    if (
        "in the remote system" in vulnerability.description
        and vulnerability.cvssv2.get("integrityImpact", "") == "PARTIAL"
    ):
        return True
    return cve_is_about_system(vulnerability.cpe_type) and vulnerability.cvssv2.get("integrityImpact", "") == "PARTIAL"


def system_availability_changed(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the vulnerability indicates a change in system availability.

    This function evaluates if the availability level has changed relative to its vulnerable state:
      - For CVSS v4.0, it compares "subsequentSystemAvailability" with "vulnerableSystemAvailability".
      - For CVSS v3.1 and v3.0, a "CHANGED" scope is used.
      - For CVSS v2, if the description contains "in the remote system" and the availability impact is PARTIAL,
        the function returns True.

    :param vulnerability: An instance of Vulnerability containing CVSS metrics, description, and CPE type.
    :return: True if system availability is changed; otherwise, False.
    """
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    if len(vulnerability.cvssv40.keys()) != 0:
        if (
            "in the remote system" in vulnerability.description
            and vulnerability.cvssv40["vulnerableSystemAvailability"] == "HIGH"
        ):
            return True
        if (
            cve_is_about_system(vulnerability.cpe_type)
            and vulnerability.cvssv40["vulnerableSystemAvailability"] == "HIGH"
        ):
            return True
    if len(vulnerability.cvssv31.keys()) != 0:
        if (
            "in the remote system" in vulnerability.description
            and vulnerability.cvssv31.get("availabilityImpact", "") == "HIGH"
        ):
            return True
        if (
            cve_is_about_system(vulnerability.cpe_type)
            and vulnerability.cvssv31.get("availabilityImpact", "") == "HIGH"
        ):
            return True
    if len(vulnerability.cvssv30.keys()) != 0:
        if (
            "in the remote system" in vulnerability.description
            and vulnerability.cvssv30.get("availabilityImpact", "") == "HIGH"
        ):
            return True
        if (
            cve_is_about_system(vulnerability.cpe_type)
            and vulnerability.cvssv30.get("availabilityImpact", "") == "HIGH"
        ):
            return True
    if (
        "in the remote system" in vulnerability.description
        and vulnerability.cvssv2.get("availabilityImpact", "") == "PARTIAL"
    ):
        return True
    return (
        cve_is_about_system(vulnerability.cpe_type) and vulnerability.cvssv2.get("availabilityImpact", "") == "PARTIAL"
    )


def add_other_cia_impacts(result_impacts: list[str], vulnerability: Vulnerability) -> None:
    """
    Adds additional CIA (Confidentiality, Integrity, Availability) impacts to the result_impacts list
    based on the vulnerability's CVSS metrics.

    This function supplements the given result_impacts list by adding any missing CIA losses if only
    one or two impacts are present. It checks CVSS v4.0, v3.1, v3.0, and v2 metrics sequentially.
    For example, if system integrity loss is present but confidentiality loss is missing and the
    CVSS confidentiality impact is LOW or PARTIAL, then "System confidentiality loss" is appended.

    :param result_impacts: A list of impact strings representing the current detected CIA losses.
    :param vulnerability: An instance of Vulnerability containing CVSS metrics and description.
    :return: None. The function modifies result_impacts in place.
    """
    if "System integrity loss" in result_impacts and "System confidentiality loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemConfidentiality", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System confidentiality loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("confidentialityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System confidentiality loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("confidentialityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System confidentiality loss")
        elif vulnerability.cvssv2.get("confidentialityImpact", "") == "PARTIAL":
            result_impacts.append("System confidentiality loss")
    if "System integrity loss" in result_impacts and "System availability loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemAvailability", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System availability loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("availabilityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System availability loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("availabilityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System availability loss")
        elif vulnerability.cvssv2.get("availabilityImpact", "") == "PARTIAL":
            result_impacts.append("System availability loss")
    if "System confidentiality loss" in result_impacts and "System integrity loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemIntegrity", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System integrity loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("integrityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System integrity loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("integrityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System integrity loss")
        elif vulnerability.cvssv2.get("integrityImpact", "") == "PARTIAL":
            result_impacts.append("System integrity loss")
    if "System confidentiality loss" in result_impacts and "System availability loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemAvailability", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System availability loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("availabilityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System availability loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("availabilityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System availability loss")
        elif vulnerability.cvssv2.get("availabilityImpact", "") == "PARTIAL":
            result_impacts.append("System availability loss")
    if "System availability loss" in result_impacts and "System confidentiality loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemConfidentiality", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System confidentiality loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("confidentialityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System confidentiality loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("confidentialityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System confidentiality loss")
        elif vulnerability.cvssv2.get("confidentialityImpact", "") == "PARTIAL":
            result_impacts.append("System confidentiality loss")
    if "System availability loss" in result_impacts and "System integrity loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemIntegrity", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System integrity loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("integrityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System integrity loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("integrityImpact", "") == "LOW" and cve_is_about_system(
                vulnerability.cpe_type
            ):
                result_impacts.append("System integrity loss")
        elif vulnerability.cvssv2.get("integrityImpact", "") == "PARTIAL":
            result_impacts.append("System integrity loss")
