def cve_is_about_system(cpe_type: set[str]) -> bool:
    """
    Determines whether a CVE targets a system component.

    This function checks the provided CPE type set to determine if the vulnerability
    is related to a system rather than an application. A vulnerability is considered
    system-related if the set contains 'o' (operating system) or 'h' (hardware) and
    does not include 'a' (application).

    :param cpe_type: A set of strings representing CPE types ('a', 'o', 'h').
    :return: True if the CVE is related to a system; otherwise, False.
    """
    return ("o" in cpe_type or "h" in cpe_type) and "a" not in cpe_type


def cve_is_about_application(cpe_type: set[str]) -> bool:
    """
    Determines whether a CVE specifically affects an application.

    This function returns True if the CPE type set contains 'a', indicating the
    vulnerability is related to an application.

    :param cpe_type: A set of strings representing CPE types ('a', 'o', 'h').
    :return: True if the CVE is about an application; otherwise, False.
    """
    return "a" in cpe_type


def test_incidence(description: str, list_of_keywords: list[str]) -> bool:
    """
    Determines if at least one of the specified keywords is present in the description.

    This function performs case-insensitive matching by converting the description
    and keywords to lowercase before checking for keyword presence.

    :param description: The textual description of the CVE.
    :param list_of_keywords: A list of keywords to search for within the description.
    :return: True if at least one keyword is found; otherwise, False.
    """
    description_lower = description.lower()
    return any(word.lower() in description_lower for word in list_of_keywords)
