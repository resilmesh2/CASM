"""
Module for Searching CVE Information via the NVD API

This module provides functions to query the National Vulnerability Database (NVD) for CVE entries
based on a specified date range, a specific CVE identifier, or a product version. The functions use
HTTP requests to access the NVD REST API and return CVE information as a list of dictionaries. Errors
are logged with specific details, and invalid inputs are validated.

Functions:
  - search_cve_by_date_range: Searches for CVEs published within a specified date range.
  - search_cve_by_id: Retrieves a CVE entry by its unique identifier.
  - search_cve_by_version: Searches for CVEs associated with a specific product and version.

Dependencies:
  - requests: For HTTP requests.
  - datetime, timedelta: For date and time handling.
  - logging: For error logging.
  - re: For CVE ID validation.
"""

import logging
import re
import time
from datetime import datetime, timedelta
from typing import Any

import requests


def search_cve_by_date_range(
    api_key: str | None = None,
    end_date: datetime = datetime.now(),
    start_date: datetime = datetime.now() - timedelta(days=30),
) -> list[dict[str, Any]] | None:
    """
    Searches for CVE entries published within a specified date range from the NVD API.

    This function queries the NVD API for CVEs published between start_date and end_date. An optional
    API key can be provided for authentication. It returns a list of CVE dictionaries if successful,
    an empty list if no CVEs are found, or None if an error occurs (e.g., HTTP 429 for rate limiting).

    :param api_key: Optional API key for NVD API authentication.
    :param end_date: End date for the search range. Defaults to current date and time.
    :param start_date: Start date for the search range. Defaults to 30 days prior to current date.
    :return: List of CVE dictionaries, empty list if none found, or None if an error occurs.
    :raises ValueError: If start_date is after end_date.
    """
    if start_date > end_date:
        logging.error("Invalid date range: start_date must be before end_date")
        raise ValueError("start_date must be before end_date")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_date.isoformat(),
        "pubEndDate": end_date.isoformat(),
    }
    headers = {"apiKey": api_key} if api_key else {}

    try:
        response = requests.get(url, headers=headers, params=params)
        # the official documentation recommends 6-second-long sleep
        time.sleep(6)
        if response.status_code == 200:
            data = response.json()
            return [vuln["cve"] for vuln in data.get("vulnerabilities", [])]
        if response.status_code == 429:
            logging.error("Rate limit exceeded (HTTP 429)")
            return None
        logging.error(f"HTTP error {response.status_code}")
        return None
    except requests.exceptions.ConnectionError:
        logging.exception("Network connection error")
        return None
    except requests.exceptions.Timeout:
        logging.exception("Request timed out")
        return None
    except requests.exceptions.RequestException as e:
        logging.exception(f"Request error: {e}")
        return None


def search_cve_by_id(cve_id: str, api_key: str | None = None) -> list[dict[str, Any]] | None:
    """
    Searches for a specific CVE entry by its unique identifier using the NVD API.

    This function queries the NVD API for the CVE specified by cve_id, which must match the format
    'CVE-YYYY-NNNN'. An optional API key can be provided. It returns a list with a single CVE
    dictionary if found, an empty list if not found, or None if an error occurs.

    :param cve_id: CVE identifier (e.g., 'CVE-2021-12345').
    :param api_key: Optional API key for NVD API authentication.
    :return: List with a single CVE dictionary, empty list if not found, or None if an error occurs.
    :raises ValueError: If cve_id format is invalid.
    """
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        logging.error(f"Invalid CVE ID format: {cve_id}")
        raise ValueError("CVE ID must match format 'CVE-YYYY-NNNN'")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"apiKey": api_key} if api_key else {}

    try:
        response = requests.get(url, headers=headers, params=params)
        # the official documentation recommends 6-second-long sleep
        time.sleep(6)
        if response.status_code == 200:
            data = response.json()
            return [data["vulnerabilities"][0]["cve"]] if data.get("vulnerabilities") else []
        if response.status_code == 429:
            logging.error(f"Rate limit exceeded for {cve_id} (HTTP 429)")
            return None
        logging.error(f"HTTP error {response.status_code} for {cve_id}")
        return None
    except requests.exceptions.ConnectionError:
        logging.exception(f"Network connection error for {cve_id}")
        return None
    except requests.exceptions.Timeout:
        logging.exception(f"Request timed out for {cve_id}")
        return None
    except requests.exceptions.RequestException as e:
        logging.exception(f"Request error for {cve_id}: {e}")
        return None


def search_cve_by_version(
    version: str,
    part: str = "a",
    api_key: str | None = None,
    start_index: int = 0,
    is_vulnerable: bool = False,
    last_mod_start_date: datetime | None = None,
    last_mod_end_date: datetime | None = None,
) -> list[dict[str, Any]] | None:
    """
    Searches for CVEs associated with a specific product and version using the NVD API.

    This function queries the NVD API for CVEs matching the specified product version in CPE format
    (e.g., 'vendor:product:version'). The part parameter specifies the CPE type ('a', 'h', or 'o').

    :param version: Product version in format 'vendor:product:version' (e.g., 'huawei:fusioncompute:8.0.0').
    :param part: CPE part ('a' for application, 'h' for hardware, 'o' for operating system). Defaults to 'a'.
    :param api_key: Optional API key for NVD API authentication.
    :param start_index: Optional index to start searching from. Defaults to 0.
    :param is_vulnerable: Optional parameter to obtain results where the product version is vulnerable. Defaults to False.
    :param last_mod_start_date: Last modified start date that constraints which vulnerabilities will be obtained. Defaults to None.
    :param last_mod_end_date: Last modified end date that constraints which vulnerabilities will be obtained. Defaults to None.
    :return: Data obtained from the NVD REST API.
    :raises ValueError: If version format or part value is invalid.
    """
    if not version or not isinstance(version, str) or version.count(":") < 2:
        logging.error(f"Invalid version format: {version}. Expected 'vendor:product:version'")
        raise ValueError("Version must be in format 'vendor:product:version'")

    if part not in ["a", "h", "o"]:
        logging.error(f"Invalid part value: {part}. Must be 'a', 'h', or 'o'")
        raise ValueError("Part must be 'a', 'h', or 'o'")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cpeName": f"cpe:2.3:{part}:{version}", "startIndex": start_index}
    if is_vulnerable:
        params["isVulnerable"] = None
    if last_mod_start_date:
        params["lastModStartDate"] = last_mod_start_date.replace("+", "%2B")
    if last_mod_end_date:
        params["lastModEndDate"] = last_mod_end_date.replace("+", "%2B")
    elif last_mod_start_date:
        params["lastModEndDate"] = (datetime.now() + timedelta(hours=1)).isoformat().replace("+", "%2B")
    params = "&".join([key if value is None else f"{key}={value}" for key, value in params.items()])
    headers = {"apiKey": api_key} if api_key else {}
    logging.info(f"Searching for CVEs for {version} (part: {part}). Last timestamp is {last_mod_start_date}.")

    try:
        response = requests.get(url, headers=headers, params=params)
        # the official documentation recommends 6-second-long sleep
        time.sleep(6)
        if response.status_code == 200:
            data = response.json()
            logging.info(f"Total results: {data['totalResults']}")
            return data
        if response.status_code == 429:
            logging.error(f"Rate limit exceeded for version {version} (HTTP 429)")
            return None
        logging.error(f"HTTP error {response.status_code} for version {version}")
        return None
    except requests.exceptions.ConnectionError:
        logging.exception(f"Network connection error for version {version}")
        return None
    except requests.exceptions.Timeout:
        logging.exception(f"Request timed out for version {version}")
        return None
    except requests.exceptions.RequestException as e:
        logging.exception(f"Request error for version {version}: {e}")
        return None
