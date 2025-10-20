"""
Module for Assessing Remote Code Execution Vulnerabilities

This module provides functions to determine whether a vulnerability enables an attacker
to execute arbitrary code on a target system. It distinguishes between code execution
with system-level (root/administrator) privileges and code execution as a non-root user.
The analysis is based on a combination of CVSS metrics from different versions (v4.0, v3.1,
v3.0, and v2) and textual analysis of the vulnerability description. These functions are designed
to be used as part of a larger vulnerability classification framework.

Functions:
  - has_code_execution_as_root: Checks if the vulnerability allows remote code execution as root/system.
  - has_code_execution_as_user: Determines if the vulnerability enables remote code execution as a non-root user.

Dependencies:
  - test_incidence, cve_is_about_system from cve_connector.nvd_cve.categorization.utils.
  - Vulnerability from cve_connector.nvd_cve.vulnerability.
"""

from cve_connector.nvd_cve.categorization.utils import cve_is_about_system, test_incidence
from cve_connector.nvd_cve.vulnerability import Vulnerability


def has_code_execution_as_root(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the given vulnerability permits remote code execution with root
    (or system-level) privileges.

    This function first scans the vulnerability description for key phrases that directly
    indicate code execution as root (using a predefined list of necessary conditions). If one of these
    phrases is found, the function returns True. Otherwise, it verifies that:
      - The vulnerability is related to a system (using its CPE type).
      - The vulnerability can execute code as a user (by invoking has_code_execution_as_user).
      - The CVSS metrics (v4.0, v3.1, v3.0, or v2) indicate a high impact on confidentiality,
        integrity, and availability.

    :param vulnerability: An instance of Vulnerability containing description, CVSS metrics, and CPE type.
    :return: True if the vulnerability allows remote code execution as root; otherwise, False.
    """
    necessary_condition: list[str] = [
        "execute arbitrary code as root",
        "execute arbitrary code with root privileges",
        "execute arbitrary code as the root user",
        "execute arbitrary code as a root user",
        "execute arbitrary code as LocalSystem",
        "execute arbitrary code as SYSTEM",
        "execute arbitrary code as Local System",
        "execute arbitrary code with SYSTEM privileges",
        "execute arbitrary code with LocalSystem privileges",
        "execute dangerous commands as root",
        "execute shell commands as the root user",
        "execute arbitrary commands as root",
        "execute arbitrary commands with root privileges",
        "execute arbitrary commands with root-level privileges",
        "execute commands as root",
        "execute root commands",
        "execute arbitrary os commands as root",
        "execute arbitrary shell commands as root",
        "execute arbitrary commands as SYSTEM",
        "execute arbitrary commands with SYSTEM privileges",
        "run commands as root",
        "run arbitrary commands as root",
        "run arbitrary commands as the root user",
        "execute code with root privileges",
        "run commands as root",
        "load malicious firmware",
        "succeed in uploading malicious Firmware",
        "executed under the SYSTEM account",
    ]
    for phrase in necessary_condition:
        if phrase in vulnerability.description:
            return True
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    if has_code_execution_as_user(vulnerability):
        if (
            len(vulnerability.cvssv40.keys()) != 0
            and vulnerability.cvssv40.get("vulnerableSystemConfidentiality", "") == "HIGH"
            and vulnerability.cvssv40.get("vulnerableSystemIntegrity", "") == "HIGH"
            and vulnerability.cvssv40.get("vulnerableSystemAvailability", "") == "HIGH"
        ):
            return True
        if (
            len(vulnerability.cvssv31.keys()) != 0
            and vulnerability.cvssv31.get("confidentialityImpact", "") == "HIGH"
            and vulnerability.cvssv31.get("integrityImpact", "") == "HIGH"
            and vulnerability.cvssv31.get("availabilityImpact", "") == "HIGH"
        ):
            return True
        if (
            len(vulnerability.cvssv30.keys()) != 0
            and vulnerability.cvssv30.get("confidentialityImpact", "") == "HIGH"
            and vulnerability.cvssv30.get("integrityImpact", "") == "HIGH"
            and vulnerability.cvssv30.get("availabilityImpact", "") == "HIGH"
        ):
            return True
        if (
            len(vulnerability.cvssv2.keys()) != 0
            and vulnerability.cvssv2.get("confidentialityImpact", "") == "COMPLETE"
            and vulnerability.cvssv2.get("integrityImpact", "") == "COMPLETE"
            and vulnerability.cvssv2.get("availabilityImpact", "") == "COMPLETE"
        ):
            return True
    return False


def has_code_execution_as_user(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the given vulnerability enables remote code execution with user-level privileges.

    The function evaluates by:
      - Scanning the description for key phrases indicating arbitrary code execution (e.g., "command injection").
      - Checking for SQL injection (non-blind) with high integrity and confidentiality impacts in CVSS metrics.
      - Assessing whether required action verbs and nouns (e.g., "execute", "code") appear in the description.

    :param vulnerability: An instance of Vulnerability containing description and CVSS metrics.
    :return: True if the vulnerability allows remote code execution as a user; otherwise, False.
    """
    necessary_condition: list[str] = [
        "include and execute arbitrary local php files",
        "execute arbitrary code",
        "command injection",
        "execute files",
        "run arbitrary code",
        "execute a malicious file",
        "execution of arbitrary code",
        "remote execution of arbitrary php code",
        "execute code",
        "code injection vulnerability",
        "execute any code",
        "malicious file could be then executed on the affected system",
        "inject arbitrary commands",
        "execute arbitrary files",
        "inject arbitrary sql code",
        "run the setuid executable",
        "vbscript injection",
        "execute administrative operations",
        "performs arbitrary actions",
        "submit arbitrary requests to an affected device",
        "perform arbitrary actions on an affected device",
        "executes an arbitrary program",
        "attacker can upload a malicious payload",
        "execute malicious code",
        "modify sql commands to the portal server",
        "execute arbitrary os commands",
        "execute arbitrary code with administrator privileges",
        "execute administrator commands",
        "executed with administrator privileges",
        "remote procedure calls on the affected system",
        "run a specially crafted application on a targeted system",
        "execute arbitrary code in a privileged context",
        "execute arbitrary code with super-user privileges",
        "run processes in an elevated context",
    ]
    for phrase in necessary_condition:
        if phrase in vulnerability.description:
            return True
    if "sql injection" in vulnerability.description and "blind sql injection" not in vulnerability.description:
        if (
            len(vulnerability.cvssv40.keys()) != 0
            and vulnerability.cvssv40.get("vulnerableSystemIntegrity", "") == "HIGH"
            and vulnerability.cvssv40.get("vulnerableSystemConfidentiality", "") == "HIGH"
        ):
            return True
        if (
            len(vulnerability.cvssv31.keys()) != 0
            and vulnerability.cvssv31.get("integrityImpact", "") == "HIGH"
            and vulnerability.cvssv31.get("confidentialityImpact", "") == "HIGH"
        ):
            return True
        if (
            len(vulnerability.cvssv30.keys()) != 0
            and vulnerability.cvssv30.get("integrityImpact", "") == "HIGH"
            and vulnerability.cvssv30.get("confidentialityImpact", "") == "HIGH"
        ):
            return True
    required_verbs: list[str] = [" execut", " run ", " inject"]
    required_nouns: list[str] = [" code ", " command", "arbitrary script", " code."]
    return bool(
        test_incidence(vulnerability.description, required_nouns)
        and test_incidence(vulnerability.description, required_verbs)
    )
