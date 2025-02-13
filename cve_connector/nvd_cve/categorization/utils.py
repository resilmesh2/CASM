from typing import Set, List


def cve_is_about_system(cpe_type: Set[str]) -> bool:
    return ('o' in cpe_type or 'h' in cpe_type) and 'a' not in cpe_type


def cve_is_about_application(cpe_type: Set[str]) -> bool:
    return 'a' in cpe_type


def test_incidence(description: str, list_of_keywords: List[str]) -> bool:
    for word in list_of_keywords:
        if word in description:
            return True
    return False
