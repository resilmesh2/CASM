
from cve_connector.nvd_cve.categorization.cia_loss import has_system_confidentiality_loss, \
    has_system_integrity_loss, has_system_availability_loss, add_other_cia_impacts, \
    system_confidentiality_changed, system_integrity_changed, system_availability_changed
from cve_connector.nvd_cve.categorization.code_execution import has_code_execution_as_root, \
    has_code_execution_as_user
from cve_connector.nvd_cve.categorization.gain_privileges import has_gain_root_privileges, \
    has_gain_user_privileges, has_privilege_escalation, has_gain_application_privileges
from cve_connector.nvd_cve.vulnerability import Vulnerability


def classifier(vulnerability: Vulnerability):
    result_impacts = test_root_level_impacts(vulnerability)
    if result_impacts:
        return result_impacts

    result_impacts = system_cia_loss(vulnerability)
    if result_impacts:
        return result_impacts

    result_impacts = test_user_level_impacts(vulnerability)
    if result_impacts:
        return result_impacts

    result_impacts = distinguish_system_application(vulnerability)
    return result_impacts


def test_root_level_impacts(vulnerability):
    result_impacts = []

    if has_code_execution_as_root(vulnerability):
        result_impacts.append(
            "Arbitrary code execution as root/administrator/system")
        return result_impacts

    if has_gain_root_privileges(vulnerability):
        result_impacts.append(
            "Gain root/system/administrator privileges on system")
        return result_impacts

    if has_privilege_escalation(vulnerability):
        result_impacts.append("Privilege escalation on system")
        return result_impacts

    return result_impacts


def system_cia_loss(vulnerability):
    result_impacts = []

    if has_system_confidentiality_loss(vulnerability):
        result_impacts.append("System confidentiality loss")

    if has_system_integrity_loss(vulnerability):
        result_impacts.append("System integrity loss")

    if has_system_availability_loss(vulnerability):
        result_impacts.append("System availability loss")

    add_other_cia_impacts(result_impacts, vulnerability)

    return result_impacts


def test_user_level_impacts(vulnerability):
    result_impacts = []
    if has_gain_user_privileges(vulnerability):
        result_impacts.append("Gain user privileges on system")
        return result_impacts

    if has_code_execution_as_user(vulnerability):
        result_impacts.append(
            "Arbitrary code execution as user of application")
        return result_impacts

    if has_gain_application_privileges(vulnerability.description):
        result_impacts.append("Gain privileges on application")
        return result_impacts

    return result_impacts


def distinguish_system_application(vulnerability):
    result_impacts = []
    if system_confidentiality_changed(vulnerability):
        result_impacts.append("System confidentiality loss")

    if system_integrity_changed(vulnerability):
        result_impacts.append("System integrity loss")

    if system_availability_changed(vulnerability):
        result_impacts.append("System availability loss")

    if not result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0 and \
            vulnerability.cvssv40["vulnerableSystemIntegrity"] != "NONE":
            result_impacts.append("Application integrity loss")
        if len(vulnerability.cvssv40.keys()) != 0 and \
            vulnerability.cvssv40["vulnerableSystemAvailability"] != "NONE":
            result_impacts.append("Application availability loss")
        if len(vulnerability.cvssv40.keys()) != 0 and \
            vulnerability.cvssv40["vulnerableSystemConfidentiality"] != "NONE":
            result_impacts.append("Application confidentiality loss")

        if len(vulnerability.cvssv31.keys()) != 0 and \
            vulnerability.cvssv31["integrityImpact"] != "NONE":
            result_impacts.append("Application integrity loss")
        if len(vulnerability.cvssv31.keys()) != 0 and \
            vulnerability.cvssv31["availabilityImpact"] != "NONE":
            result_impacts.append("Application availability loss")
        if len(vulnerability.cvssv31.keys()) != 0 and \
            vulnerability.cvssv31["confidentialityImpact"] != "NONE":
            result_impacts.append("Application confidentiality loss")

        if len(vulnerability.cvssv30.keys()) != 0 and \
            vulnerability.cvssv30["integrityImpact"] != "NONE":
            result_impacts.append("Application integrity loss")
        if len(vulnerability.cvssv30.keys()) != 0 and \
            vulnerability.cvssv30["availabilityImpact"] != "NONE":
            result_impacts.append("Application availability loss")
        if len(vulnerability.cvssv30.keys()) != 0 and \
            vulnerability.cvssv30["confidentialityImpact"] != "NONE":
            result_impacts.append("Application confidentiality loss")

    return result_impacts

