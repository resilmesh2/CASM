from typing import Set, List


from cve_connector.nvd_cve.categorization.utils import test_incidence, cve_is_about_system
from cve_connector.nvd_cve.vulnerability import Vulnerability


def has_system_confidentiality_loss(vulnerability):
    sufficient_condition = [
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
        if vulnerability.cvssv40.get("vulnerableSystemConfidentiality") == "LOW":
            if test_incidence(vulnerability.description, sufficient_condition):
                return True
        return vulnerability.cvssv40.get("vulnerableSystemConfidentiality") == "HIGH"
    

    if len(vulnerability.cvssv31.keys()) != 0:
        if vulnerability.cvssv31.get("confidentialityImpact") == "LOW":
            if test_incidence(vulnerability.description, sufficient_condition):
                return True
        return vulnerability.cvssv31.get("confidentialityImpact") == "HIGH"


    if len(vulnerability.cvssv30.keys()) != 0:
        if vulnerability.cvssv30.get("confidentialityImpact") == "LOW":
            if test_incidence(vulnerability.description, sufficient_condition):
                return True
        return vulnerability.cvssv30.get("confidentialityImpact") == "HIGH"


    if vulnerability.cvssv2["confidentialityImpact"] == "PARTIAL":
        if test_incidence(vulnerability.description, sufficient_condition):
            return True

    return vulnerability.cvssv2["confidentialityImpact"] == "COMPLETE"

    
def has_system_integrity_loss(vulnerability):
    if not cve_is_about_system(vulnerability.cpe_type):
        return False

    sufficient_condition = [
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
        "host arbitrary files"
    ]

    if len(vulnerability.cvssv40.keys()) != 0:
        if vulnerability.cvssv40.get("vulnerableSystemIntegrity") == "LOW":
            if test_incidence(vulnerability.description, sufficient_condition):
                return True
        return vulnerability.cvssv40.get("vulnerableSystemIntegrity") == "HIGH"
    

    if len(vulnerability.cvssv31.keys()) != 0:
        if vulnerability.cvssv31.get("integrityImpact") == "LOW":
            if test_incidence(vulnerability.description, sufficient_condition):
                return True
        return vulnerability.cvssv31.get("integrityImpact") == "HIGH"


    if len(vulnerability.cvssv30.keys()) != 0:
        if vulnerability.cvssv30.get("integrityImpact") == "LOW":
            if test_incidence(vulnerability.description, sufficient_condition):
                return True
        return vulnerability.cvssv30.get("integrityImpact") == "HIGH"


    if vulnerability.cvssv2["integrityImpact"] == "PARTIAL":
        if test_incidence(vulnerability.description, sufficient_condition):
            return True

    return vulnerability.cvssv2["integrityImpact"] == "COMPLETE"


def has_system_availability_loss(vulnerability):
    if not cve_is_about_system(vulnerability.cpe_type):
        return False

    system_tokens = [
        'device crash',
        'device reload',
        'system crash',
        'cpu consumption'
    ]

    for token in system_tokens:
        if token in vulnerability.description:
            return True

    sufficient_condition = [
        "an extended denial of service condition for the device",
        "exhaust the memory resources of the machine",
        "denial of service (dos) condition on an affected device",
        "crash systemui",
        "denial of service (dos) condition on the affected appliance",
        "cause the device to hang or unexpectedly reload",
        "denial of service (use-after-free) via a crafted application",
        "cause an affected device to reload",
        "cause an affected system to stop"
    ]

    if len(vulnerability.cvssv40.keys()) != 0:
        if vulnerability.cvssv40["vulnerableSystemAvailability"] == "LOW":
            if test_incidence(vulnerability.description, sufficient_condition):
                return True
        if has_system_integrity_loss(vulnerability):
            return vulnerability.cvssv40["vulnerableSystemAvailability"] != 'NONE'
        else:
            return vulnerability.cvssv40["vulnerableSystemAvailability"] == 'HIGH'
    

    if len(vulnerability.cvssv31.keys()) != 0:
        if vulnerability.cvssv31["availabilityImpact"] == "LOW":
            if test_incidence(vulnerability.description, sufficient_condition):
                return True
        if has_system_integrity_loss(vulnerability):
            return vulnerability.cvssv31["availabilityImpact"] != 'NONE'
        else:
            return vulnerability.cvssv31["availabilityImpact"] == 'HIGH'


    if len(vulnerability.cvssv30.keys()) != 0:
        if vulnerability.cvssv30["availabilityImpact"] == "LOW":
            if test_incidence(vulnerability.description, sufficient_condition):
                return True
        if has_system_integrity_loss(vulnerability):
            return vulnerability.cvssv30["availabilityImpact"] != 'NONE'
        else:
            return vulnerability.cvssv30["availabilityImpact"] == 'HIGH'


    if vulnerability.cvssv2["availabilityImpact"] == "PARTIAL":
        if test_incidence(vulnerability.description, sufficient_condition):
            return True
    
    if has_system_integrity_loss(vulnerability):
        return vulnerability.cvssv2["availabilityImpact"] != 'NONE'
    else:
        return vulnerability.cvssv2["availabilityImpact"] == 'COMPLETE'


def system_confidentiality_changed(vulnerability):
    if not cve_is_about_system(vulnerability.cpe_type):
        return False

    if len(vulnerability.cvssv40.keys()) != 0:
        return vulnerability.cvssv40["subsequentSystemConfidentiality"] != vulnerability.cvssv40.get("vulnerableSystemConfidentiality")
    
    if len(vulnerability.cvssv31.keys()) != 0:
        return vulnerability.cvssv31["scope"] == "CHANGED"

    if len(vulnerability.cvssv30.keys()) != 0:
        return vulnerability.cvssv30["scope"] == "CHANGED"

    if "in the remote system" in vulnerability.description and vulnerability.cvssv2["confidentialityImpact"] == "PARTIAL":
        return True

    return cve_is_about_system(vulnerability.cpe_type) and vulnerability.cvssv2["confidentialityImpact"] == "PARTIAL"


def system_integrity_changed(vulnerability):
    if not cve_is_about_system(vulnerability.cpe_type):
        return False

    if len(vulnerability.cvssv40.keys()) != 0:
        return vulnerability.cvssv40["subsequentSystemIntegrity"] != vulnerability.cvssv40.get("subsequentSystemIntegrity")
    
    if len(vulnerability.cvssv31.keys()) != 0:
        return vulnerability.cvssv31["scope"] == "CHANGED"

    if len(vulnerability.cvssv30.keys()) != 0:
        return vulnerability.cvssv30["scope"] == "CHANGED"

    if "in the remote system" in vulnerability.description and vulnerability.cvssv2["integrityImpact"] == "PARTIAL":
        return True

    return cve_is_about_system(vulnerability.cpe_type) and vulnerability.cvssv2["integrityImpact"] == "PARTIAL"


def system_availability_changed(vulnerability):
    if not cve_is_about_system(vulnerability.cpe_type):
        return False

    if len(vulnerability.cvssv40.keys()) != 0:
        return vulnerability.cvssv40["subsequentSystemAvailability"] != vulnerability.cvssv40.get("subsequentSystemAvailability")
    
    if len(vulnerability.cvssv31.keys()) != 0:
        return vulnerability.cvssv31["scope"] == "CHANGED"

    if len(vulnerability.cvssv30.keys()) != 0:
        return vulnerability.cvssv30["scope"] == "CHANGED"
    
    if "in the remote system" in vulnerability.description and vulnerability.cvssv2["availabilityImpact"] == "PARTIAL":
        return True

    return cve_is_about_system(vulnerability.cpe_type) and vulnerability.cvssv2["availabilityImpact"] == "PARTIAL"


def add_other_cia_impacts(result_impacts, vulnerability):
    if not cve_is_about_system(vulnerability.cpe_type):
        return

    if "System integrity loss" in result_impacts and \
            "System confidentiality loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemConfidentiality") == "LOW":
                result_impacts.append("System confidentiality loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("confidentialityImpact") == "LOW":   
                result_impacts.append("System confidentiality loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("confidentialityImpact") == "LOW":   
                result_impacts.append("System confidentiality loss")
        elif vulnerability.cvssv2["confidentialityImpact"] == "PARTIAL":
            result_impacts.append("System confidentiality loss")

    if "System integrity loss" in result_impacts and \
            "System availability loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemAvailability") == "LOW":
                result_impacts.append("System availability loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("availabilityImpact") == "LOW":   
                result_impacts.append("System availability loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("availabilityImpact") == "LOW":   
                result_impacts.append("System availability loss")
        elif vulnerability.cvssv2["availabilityImpact"] == "PARTIAL":
            result_impacts.append("System availability loss")

    if "System confidentiality loss" in result_impacts and \
            "System integrity loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemIntegrity") == "LOW":
                result_impacts.append("System integrity loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("integrityImpact") == "LOW":   
                result_impacts.append("System integrity loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("integrityImpact") == "LOW":   
                result_impacts.append("System integrity loss")
        elif vulnerability.cvssv2["integrityImpact"] == "PARTIAL":
            result_impacts.append("System integrity loss")

    if "System confidentiality loss" in result_impacts and \
            "System availability loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemAvailability") == "LOW":
                result_impacts.append("System availability loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("availabilityImpact") == "LOW":   
                result_impacts.append("System availability loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("availabilityImpact") == "LOW":   
                result_impacts.append("System availability loss")
        elif vulnerability.cvssv2["availabilityImpact"] == "PARTIAL":
            result_impacts.append("System availability loss")

    if "System availability loss" in result_impacts and \
            "System confidentiality loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemConfidentiality") == "LOW":
                result_impacts.append("System confidentiality loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("confidentialityImpact") == "LOW":   
                result_impacts.append("System confidentiality loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("confidentialityImpact") == "LOW":   
                result_impacts.append("System confidentiality loss")
        elif vulnerability.cvssv2["confidentialityImpact"] == "PARTIAL":
            result_impacts.append("System confidentiality loss")

    if "System availability loss" in result_impacts and \
            "System integrity loss" not in result_impacts:
        if len(vulnerability.cvssv40.keys()) != 0:
            if vulnerability.cvssv40.get("vulnerableSystemIntegrity") == "LOW":
                result_impacts.append("System integrity loss")
        elif len(vulnerability.cvssv31.keys()) != 0:
            if vulnerability.cvssv31.get("integrityImpact") == "LOW":   
                result_impacts.append("System integrity loss")
        elif len(vulnerability.cvssv30.keys()) != 0:
            if vulnerability.cvssv30.get("integrityImpact") == "LOW":   
                result_impacts.append("System integrity loss")
        elif vulnerability.cvssv2["integrityImpact"] == "PARTIAL":
            result_impacts.append("System integrity loss")
