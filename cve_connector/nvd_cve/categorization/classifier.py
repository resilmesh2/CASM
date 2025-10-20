"""
Module for Classifying Vulnerability Impacts

This module aggregates the impact analysis of a vulnerability by combining multiple assessments,
including system and application CIA losses, remote code execution, and privilege gain. The classifier
sequentially applies a series of impact tests and returns the first set of detected impacts as a list of strings.
This framework is designed to integrate with broader vulnerability analysis and classification systems.

Functions:
  - classifier: Orchestrates the overall classification process.
  - test_root_level_impacts: Evaluates root-level impacts such as code execution as root or privilege escalation.
  - system_cia_loss: Assesses system confidentiality, integrity, and availability losses.
  - test_user_level_impacts: Evaluates user-level and application-level impacts.
  - distinguish_system_application: Differentiates between system and application impacts using CVSS metrics.

Dependencies:
  - Functions from cve_connector.nvd_cve.categorization.cia_loss, code_execution, and gain_privileges.
  - Vulnerability from cve_connector.nvd_cve.vulnerability.
"""

from cve_connector.nvd_cve.categorization.cia_loss import (
    add_other_cia_impacts,
    has_system_availability_loss,
    has_system_confidentiality_loss,
    has_system_integrity_loss,
    system_availability_changed,
    system_confidentiality_changed,
    system_integrity_changed,
)
from cve_connector.nvd_cve.categorization.code_execution import has_code_execution_as_root, has_code_execution_as_user
from cve_connector.nvd_cve.categorization.gain_privileges import (
    has_gain_application_privileges,
    has_gain_root_privileges,
    has_gain_user_privileges,
    has_privilege_escalation,
)
from cve_connector.nvd_cve.vulnerability import Vulnerability


def classifier(vulnerability: Vulnerability) -> list[str]:
    """
    Classifies a vulnerability by sequentially evaluating its potential impacts.

    The classification process occurs in four stages:
      1. Test for root-level impacts (e.g., remote code execution as root, gain of root privileges, privilege escalation).
      2. Assess system CIA (confidentiality, integrity, availability) loss.
      3. Test for user-level impacts (e.g., gain of user privileges or code execution as an application user).
      4. Distinguish between system and application impacts based on CVSS metrics if no impacts were detected above.

    :param vulnerability: An instance of Vulnerability containing description, CVSS metrics, and CPE type.
    :return: A list of impact strings classifying the vulnerability.
    """
    result_impacts: list[str] = test_root_level_impacts(vulnerability)
    if result_impacts:
        return result_impacts
    result_impacts = system_cia_loss(vulnerability)
    if result_impacts:
        return result_impacts
    result_impacts = test_user_level_impacts(vulnerability)
    if result_impacts:
        return result_impacts
    return distinguish_system_application(vulnerability)


def test_root_level_impacts(vulnerability: Vulnerability) -> list[str]:
    """
    Tests whether the vulnerability exhibits any root-level impacts.

    The function checks for:
      - Arbitrary code execution as root/administrator/system.
      - Gain of root/system/administrator privileges.
      - Privilege escalation on the system.

    The checks are performed sequentially, and the first matching impact is returned.

    :param vulnerability: An instance of Vulnerability.
    :return: A list of impact strings with one element if a root-level impact is detected; otherwise, an empty list.
    """
    result_impacts: list[str] = []
    if has_code_execution_as_root(vulnerability):
        result_impacts.append("Arbitrary code execution as root/administrator/system")
        return result_impacts
    if has_gain_root_privileges(vulnerability):
        result_impacts.append("Gain root/system/administrator privileges on system")
        return result_impacts
    if has_privilege_escalation(vulnerability):
        result_impacts.append("Privilege escalation on system")
        return result_impacts
    return result_impacts


def system_cia_loss(vulnerability: Vulnerability) -> list[str]:
    """
    Determines if the vulnerability causes system CIA (confidentiality, integrity, availability) loss.

    The function checks for direct indications of:
      - System confidentiality loss.
      - System integrity loss.
      - System availability loss.

    It invokes add_other_cia_impacts to include any additional CIA-related impacts based on CVSS metrics.

    :param vulnerability: An instance of Vulnerability.
    :return: A list of impact strings representing detected system CIA losses.
    """
    result_impacts: list[str] = []
    if has_system_confidentiality_loss(vulnerability):
        result_impacts.append("System confidentiality loss")
    if has_system_integrity_loss(vulnerability):
        result_impacts.append("System integrity loss")
    if has_system_availability_loss(vulnerability):
        result_impacts.append("System availability loss")
    add_other_cia_impacts(result_impacts, vulnerability)
    return result_impacts


def test_user_level_impacts(vulnerability: Vulnerability) -> list[str]:
    """
    Tests whether the vulnerability exhibits any user-level impacts.

    This function evaluates:
      - Gain of user privileges on the system.
      - Arbitrary code execution as a user of the application.
      - Gain of privileges within an application context.

    The check is sequential; once an impact is detected, it is returned immediately.

    :param vulnerability: An instance of Vulnerability.
    :return: A list of impact strings with one element if a user-level impact is detected; otherwise, an empty list.
    """
    result_impacts: list[str] = []
    if has_gain_user_privileges(vulnerability):
        result_impacts.append("Gain user privileges on system")
        return result_impacts
    if has_code_execution_as_user(vulnerability):
        result_impacts.append("Arbitrary code execution as user of application")
        return result_impacts
    if has_gain_application_privileges(vulnerability.description):
        result_impacts.append("Gain privileges on application")
        return result_impacts
    return result_impacts


def distinguish_system_application(vulnerability: Vulnerability) -> list[str]:
    """
    Distinguishes between system-level and application-level impacts when no clear CIA loss is detected.

    The function first checks for system CIA changes (via system_confidentiality_changed,
    system_integrity_changed, or system_availability_changed). If none are found, it evaluates
    CVSS metrics (v4.0, v3.1, v3.0) to identify application-level impacts (confidentiality,
    integrity, or availability loss).

    :param vulnerability: An instance of Vulnerability.
    :return: A list of impact strings classifying the vulnerability as affecting system or application components.
    """
    result_impacts: list[str] = []
    if system_confidentiality_changed(vulnerability):
        result_impacts.append("System confidentiality loss")
    if system_integrity_changed(vulnerability):
        result_impacts.append("System integrity loss")
    if system_availability_changed(vulnerability):
        result_impacts.append("System availability loss")
    if not result_impacts:
        if (
            len(vulnerability.cvssv40.keys()) != 0
            and vulnerability.cvssv40.get("vulnerableSystemIntegrity", "") != "NONE"
        ):
            result_impacts.append("Application integrity loss")
        if (
            len(vulnerability.cvssv40.keys()) != 0
            and vulnerability.cvssv40.get("vulnerableSystemAvailability", "") != "NONE"
        ):
            result_impacts.append("Application availability loss")
        if (
            len(vulnerability.cvssv40.keys()) != 0
            and vulnerability.cvssv40.get("vulnerableSystemConfidentiality", "") != "NONE"
        ):
            result_impacts.append("Application confidentiality loss")
        if len(vulnerability.cvssv31.keys()) != 0 and vulnerability.cvssv31.get("integrityImpact", "") != "NONE":
            result_impacts.append("Application integrity loss")
        if len(vulnerability.cvssv31.keys()) != 0 and vulnerability.cvssv31.get("availabilityImpact", "") != "NONE":
            result_impacts.append("Application availability loss")
        if len(vulnerability.cvssv31.keys()) != 0 and vulnerability.cvssv31.get("confidentialityImpact", "") != "NONE":
            result_impacts.append("Application confidentiality loss")
        if len(vulnerability.cvssv30.keys()) != 0 and vulnerability.cvssv30.get("integrityImpact", "") != "NONE":
            result_impacts.append("Application integrity loss")
        if len(vulnerability.cvssv30.keys()) != 0 and vulnerability.cvssv30.get("availabilityImpact", "") != "NONE":
            result_impacts.append("Application availability loss")
        if len(vulnerability.cvssv30.keys()) != 0 and vulnerability.cvssv30.get("confidentialityImpact", "") != "NONE":
            result_impacts.append("Application confidentiality loss")
    return result_impacts
