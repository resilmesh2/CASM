"""
Module for Assessing Privilege Gain Vulnerabilities

This module provides functions to determine whether a vulnerability allows an attacker to gain
additional privileges on a target system. The analysis distinguishes between privilege escalation
at the system level (e.g., root/administrator privileges), user-level privilege gain, and application-level
privilege gain. The evaluation is based on both CVSS metrics from various versions (v4.0, v3.1, v3.0, and v2)
and textual analysis of the vulnerability description. These functions are intended for integration
within a comprehensive vulnerability classification framework.

Functions:
  - has_gain_root_privileges: Checks if the vulnerability permits gaining root/system privileges.
  - has_privilege_escalation: Determines if the vulnerability leads to privilege escalation.
  - has_gain_application_privileges: Evaluates if the vulnerability allows application-level privilege gain.
  - has_gain_user_privileges: Assesses whether the vulnerability enables user-level privilege gain.

Dependencies:
  - test_incidence, cve_is_about_application, cve_is_about_system from cve_connector.nvd_cve.categorization.utils.
  - Vulnerability from cve_connector.nvd_cve.vulnerability.
"""

from cve_connector.nvd_cve.categorization.utils import cve_is_about_application, cve_is_about_system, test_incidence
from cve_connector.nvd_cve.vulnerability import Vulnerability


def test_privileges(description: str) -> bool:
    """
    Determines if the given vulnerability description indicates an attempt to gain privileges.

    This function checks for phrases or keywords suggesting privilege escalation or
    unauthorized access, including generic patterns (e.g., "gain" and "privilege") or
    specific phrases (e.g., bypassing authentication during admin login).

    :param description: The vulnerability description text.
    :return: True if the description suggests privilege gain; otherwise, False.
    """
    condition: list[str] = [
        "root privilege",
        "obtain root access",
        "elevation of privilege vulnerability",
        "privilege escalation",
        "escalation of privilege",
        "escalate privileges",
        "default password",
        "arbitrary password change",
        "escalate",
        "assume the identity of another user",
        "password in configuration file",
        "hardcoded login credentials",
        "passwords are encoded in hexadecimal",
        "passwords are in cleartext",
        "cleartext password storage",
        "obtain admin privilege",
        "obtain administrator privilege",
        "gain administrative rights",
        "gain administrative access",
        "gain administrator access",
        "gain administrator level access",
        "gain administrator rights",
        "obtain the cleartext administrator password",
        "steal the administrator password",
        "obtain the administrator password",
        "obtain the administrator's password",
        "read the administrator password",
        "obtain administrator password",
        "read the administrator's password",
        "discover the administrator password",
        "discover cleartext administrator password",
        "read the admin password",
        "obtain the admin password",
        "receive the admin password",
        "obtain the administrative password",
        "retrieve the administrative password",
        "obtain administrative password",
        "read the administrative password",
        "read administrative password",
        "gain full administrative control",
        "obtain privileged host OS access",
        "log in to the device with elevated privileges",
        "higher level of privileges",
        "change the admin password",
        "default passwords",
        "backdoor admin account",
        "hardcoded username / password",
        "administrator privileges",
        "default system account",
        "automatically logs in as admin",
        "creation of fully privileged new users",
        "user is logged in without being prompted for a password",
        "different privileges then the original requester",
        "obtain control",
        "steal any active admin session",
        "reset the admin password",
        "assuming the identity of a privileged user",
        "obtain privileged host OS access",
        "change the admin password",
        "log in to an affected system as the linux admin user",
        "escalate his or her privileges",
        "launch a process with escalated privileges",
        "to the system with the same level of privilege as the application",
        "reset the admin password",
        "assuming the identity of a privileged user",
        "obtain sensitive domain administrator password information",
        "does not properly mitigate brute-force attacks",
        "allows anyone to authenticate",
        "execute actions that they do not have access to",
        "compromise user accounts",
        "brute force account credentials",
        "user credentials in plain text",
        "actions they do not have access to",
        "execute a report they do not have access to",
        "hijack the authentication of administrators",
        "bypass the application-level authentication",
        "impersonate other users",
        "access user credentials",
        "access to password information",
        "gain administrator functionality",
        "allow plaintext credentials to be obtained",
        "escalate their privileges",
        "credentials in a browser's local storage without expiration",
        "allowing users to elevate their privileges",
        "using the authenticated user's privileges",
        "potential reuse of domain credentials",
        "administrative access to the application",
        "default passwords",
        "on behalf of the currently logged in user",
        "gain privileged access",
        "do not have any option to change their own passwords",
        "create a new admin user",
        "hijack the authentication",
        "gain login access",
        "reset the registered user's password",
        "default privileged account",
        "login with the hashed password",
        "skip authentication checks",
        "hard-coded passwords",
        "hardcoded username and password",
        "local-privilege-escalation",
        "elevation of privileges",
        "include sensitive information such as account passwords",
        "account takeover",
        "obtaining admin privileges",
        "arbitrary password reset",
        "missing brute force protection",
        "makes brute-force attacks easier",
        "numeric password with a small maximum character size",
        "improper authentication issue",
        "gain access to moderator/admin accounts",
        "create new administrator user accounts",
        "take over the entire application",
        "add an administrator account",
        "plain text password",
        "possibly escalating privileges",
        "hijack oauth sessions of other users",
        "allows guest os users to obtain xen privileges",
        "gain access via cookie reuse",
        "password exposure",
        "obtain credentials",
        "resumption of an unauthenticated session",
        "no authorization check when connecting to the device",
        "incorrect authorization check",
        "hijack the authentication of logged administrators",
        "unrestricted access",
        "perform a password reset for users",
        "obtaining administrative permissions",
        "escalate privileges",
        "discloses foreign server passwords",
        "password leak",
        "disclosure of the master password",
        "submit authenticated requests",
        "takeover",
        "perform actions with the privileges of an authenticated user",
        "bypass authentication without obtaining the actual password",
        "take over the administrative session",
        "reset the password of the admin user",
        "gain guest os privileges",
        "reset the admin password",
        "change the administrator account password",
        "plaintext storage of a password",
        "password is stored in clear text",
        "default administrative password",
        "default password of admin",
        "receive the admin password",
        "steal a user's credentials",
        "dictionary attacks",
        "perform operations on device with administrative privileges",
        "include user credentials",
    ]
    if "gain" in description and "privilege" in description:
        return True
    if "bypass authentication" in description and "during an admin login attempt" in description:
        return True
    return test_incidence(description, condition)


def has_root_privileges_description(description: str) -> bool:
    """
    Determines if the given vulnerability description indicates an attempt to gain root privileges.

    The function scans for phrases explicitly mentioning root or system-level privileges.
    A special case is handled for default password scenarios including "default", "password",
    and "for the root".

    :param description: The vulnerability description text.
    :return: True if the description indicates root privilege gain; otherwise, False.
    """
    condition: list[str] = [
        "with the privileges of the root user",
        "add root ssh key",
        "gain root privilege",
        "obtain root privilege",
        "leading to root privilege",
        "gains root privilege",
        "gain SYSTEM privilege",
        "obtain SYSTEM privilege",
        "gain LocalSystem privilege",
        "obtain LocalSystem privilege",
        "gain full privilege",
        "gain root access",
        "gain root rights",
        "gain root privileges",
        "gain system level access to a remote shell session",
        "gain administrator or system privileges",
        "leading to root privileges",
        "obtain the root password",
        "take complete control of the device",
        "take full control of the target system",
        "account could be granted root- or system-level privileges",
        "find the root credentials",
        "backdoor root account",
        "elevate the privileges to root",
        "leading to remote root",
        "take control of the affected device",
        "gain complete control",
        "gain full access to the affected system",
        "obtain full access",
        "gain complete control of the system",
        "SYSTEM",
        "elevate privileges to the root user",
        "obtain full control",
    ]
    if "default" in description and "password" in description and "for the root" in description:
        return True
    return test_incidence(description, condition)


def has_gain_root_privileges(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the given vulnerability enables a gain of root (or system-level) privileges.

    The evaluation includes:
      - Confirming the vulnerability targets a system (via CPE type).
      - Checking CVSS v4.0, v3.1, and v3.0 metrics to ensure "privilegesRequired" is "NONE".
      - For CVSS v2, assessing the 'obtainAllPrivilege' flag and impact metrics with description-based checks.

    :param vulnerability: An instance of Vulnerability containing description, CVSS metrics, and CPE type.
    :return: True if the vulnerability allows root privilege gain; otherwise, False.
    """
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    if len(vulnerability.cvssv40.keys()) != 0 and vulnerability.cvssv40.get("privilegesRequired", "") != "NONE":
        return False
    if len(vulnerability.cvssv31.keys()) != 0 and vulnerability.cvssv31.get("privilegesRequired", "") != "NONE":
        return False
    if len(vulnerability.cvssv30.keys()) != 0 and vulnerability.cvssv30.get("privilegesRequired", "") != "NONE":
        return False
    if len(vulnerability.cvssv2.keys()) != 0 and vulnerability.cvssv2.get("obtainAllPrivilege", "") == "true":
        return True
    if has_root_privileges_description(vulnerability.description):
        return True
    return (
        len(vulnerability.cvssv2.keys()) != 0
        and vulnerability.cvssv2.get("confidentialityImpact", "") == "COMPLETE"
        and vulnerability.cvssv2.get("integrityImpact", "") == "COMPLETE"
        and vulnerability.cvssv2.get("availabilityImpact", "") == "COMPLETE"
        and test_privileges(vulnerability.description)
    )


def has_privilege_escalation(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the given vulnerability facilitates privilege escalation on a system.

    The check verifies:
      - The vulnerability is system-related (using CPE type).
      - Explicit indications of root privilege gain in the description.
      - CVSS v2 impact metrics (confidentiality, integrity, availability) with privilege escalation patterns.

    :param vulnerability: An instance of Vulnerability with CVE details.
    :return: True if the vulnerability leads to privilege escalation; otherwise, False.
    """
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    if len(vulnerability.cvssv2.keys()) != 0 and vulnerability.cvssv2.get("obtainAllPrivilege", "") == "true":
        return True
    if has_root_privileges_description(vulnerability.description):
        return True
    return (
        len(vulnerability.cvssv2.keys()) != 0
        and vulnerability.cvssv2.get("confidentialityImpact", "") == "COMPLETE"
        and vulnerability.cvssv2.get("integrityImpact", "") == "COMPLETE"
        and vulnerability.cvssv2.get("availabilityImpact", "") == "COMPLETE"
        and test_privileges(vulnerability.description)
    )


def has_gain_application_privileges(description: str) -> bool:
    """
    Determines if the vulnerability description indicates potential to gain privileges within an application.

    This function checks for phrases suggesting privilege escalation or unauthorized access
    within an application context, using the same textual analysis as test_privileges.

    :param description: The vulnerability description text.
    :return: True if the description implies application-level privilege gain; otherwise, False.
    """
    return test_privileges(description)


def has_gain_user_privileges(vulnerability: Vulnerability) -> bool:
    """
    Determines whether the given vulnerability enables an attacker to gain user-level privileges on a system.

    The analysis includes:
      - Checking if the CVSS v2 'obtainUserPrivilege' flag is 'true'.
      - Searching for phrases indicating login with elevated or default credentials.
      - Verifying the vulnerability is not exclusively application-related.

    :param vulnerability: An instance of Vulnerability containing CVE details.
    :return: True if the vulnerability allows user privilege gain; otherwise, False.
    """
    if not cve_is_about_system(vulnerability.cpe_type):
        return False
    if vulnerability.cvssv2.get("obtainUserPrivilege", "") == "true":
        return True
    system_tokens: list[str] = [
        "gain elevated privileges on the system",
        "with the knowledge of the default password may login to the system",
        "log in as an admin user of the affected device",
        "log in as an admin or oper user of the affected device",
        "log in to the affected device using default credentials",
        "log in to an affected system as the admin user",
        "log in to the device with the privileges of a limited user",
        "devices have a hardcoded-key vulnerability",
    ]
    for phrase in system_tokens:
        if phrase in vulnerability.description:
            return True
    return not cve_is_about_application(vulnerability.cpe_type) and test_privileges(vulnerability.description)
