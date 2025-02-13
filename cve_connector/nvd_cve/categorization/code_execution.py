
from cve_connector.nvd_cve.categorization.utils import test_incidence, cve_is_about_system
from cve_connector.nvd_cve.vulnerability import Vulnerability


def has_code_execution_as_root(vulnerability):
    necessary_condition = [
        "execute arbitrary code as root",
        "execute arbitrary code with root privileges",
        "execute arbitrary code as the root user",
        "execute arbitrary code as a root user",
        "execute arbitrary code as LocalSystem",
        "execute arbitrary code as SYSTEM",
        "execute arbitrary code as Local System"
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
        "executed under the SYSTEM account"
    ] #execute code in the context of root ??

    for phrase in necessary_condition:
        if phrase in vulnerability.description:
            return True
    
    if not cve_is_about_system(vulnerability.cpe_type):
        return False

    if has_code_execution_as_user(vulnerability):
        if len(vulnerability.cvssv40.keys()) != 0 and \
            (vulnerability.cvssv40["vulnerableSystemConfidentiality"] == "HIGH") and (vulnerability.cvssv40["vulnerableSystemIntegrity"] == "HIGH") and (vulnerability.cvssv40["vulnerableSystemAvailability"] == "HIGH"):
            return True
        if len(vulnerability.cvssv31.keys()) != 0 and \
            (vulnerability.cvssv31["confidentialityImpact"] == "HIGH") and (vulnerability.cvssv31["integrityImpact"] == "HIGH") and (vulnerability.cvssv31["availabilityImpact"] == "HIGH"):
            return True
        if len(vulnerability.cvssv30.keys()) != 0 and \
            (vulnerability.cvssv30["confidentialityImpact"] == "HIGH") and (vulnerability.cvssv30["integrityImpact"] == "HIGH") and (vulnerability.cvssv30["availabilityImpact"] == "HIGH"):
            return True
        if len(vulnerability.cvssv2.keys()) != 0 and \
            (vulnerability.cvssv2["confidentialityImpact"] == "COMPLETE") and (vulnerability.cvssv2["integrityImpact"] == "COMPLETE") and (vulnerability.cvssv2["availabilityImpact"] == "COMPLETE"):
            return True
    return False


def has_code_execution_as_user(vulnerability):
    necessary_condition = [
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
        if len(vulnerability.cvssv40.keys()) != 0 and \
            vulnerability.cvssv40["vulnerableSystemIntegrity"] == "HIGH" and vulnerability.cvssv40["vulnerableSystemConfidentiality"] == "HIGH":
            return True
        if len(vulnerability.cvssv31.keys()) != 0 and \
            vulnerability.cvssv31["integrityImpact"] == "HIGH" and vulnerability.cvssv31["confidentialityImpact"] == "HIGH":
            return True
        if len(vulnerability.cvssv30.keys()) != 0 and \
            vulnerability.cvssv30["integrityImpact"] == "HIGH" and vulnerability.cvssv30["confidentialityImpact"] == "HIGH":
            return True

    required_verbs = [
        " execut",
        " run ",
        ' inject'
    ]
    required_nouns = [
        " code ",
        " command",
        "arbitrary script",
        " code."
    ]

    if test_incidence(vulnerability.description, required_nouns) and \
            test_incidence(vulnerability.description, required_verbs):
        return True

    return False
