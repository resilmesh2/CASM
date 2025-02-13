import requests
import logging

from typing import List, Dict, Any
from datetime import datetime, timedelta

from cve_connector.nvd_cve.cve_parser import parse_vulnerabilities
from cve_connector.nvd_cve.toneo4j import move_cve_data_to_neo4j

def search_cve_by_date_range_pagination(api_key: str | None = None, neo4j_bolt: str = "bolt://localhost:7687",
                                        neo4j_password: str | None = None,
                             end_date: datetime = datetime.now(),
                             start_date: datetime = datetime.now() - timedelta(days=30)
                             ) -> List[Dict[str, Any]] | None:

    required_timedelta = end_date - start_date

    # maximum timedelta allowed in NVD REST API is 120 days
    iterations = (required_timedelta.days // 100) + 1
    original_end_date = end_date
    end_date = start_date + timedelta(days=100)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'pubStartDate': start_date.isoformat(),
        'pubEndDate': end_date.isoformat(),
        'startIndex': 0
    }
    headers = {}

    if api_key:
        headers['apiKey'] = api_key
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            for i in range(iterations):
                while data['startIndex'] + data['resultsPerPage'] < data['totalResults']:
                    cve_info: List[Dict[str, Any]] = []
                    if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                        for vuln in data["vulnerabilities"]:
                            cve_info.append(vuln["cve"])
                    parsed_data = parse_vulnerabilities(data=cve_info)
                    move_cve_data_to_neo4j(parsed_data, neo4j_bolt, neo4j_password)

                    params['startIndex'] = data['startIndex'] + data['resultsPerPage']

                    response = requests.get(url, headers=headers, params=params)
                    if response.status_code == 200:
                        data = response.json()
                    else:
                        logging.error(f"Error: HTTP {response.status_code}")

                start_date = end_date
                end_date = end_date + timedelta(days=100)
                if end_date > original_end_date:
                    end_date = original_end_date
                params['pubStartDate'] = start_date.isoformat()
                params['pubEndDate'] = end_date.isoformat()
                params['startIndex'] = 0

                response = requests.get(url, headers=headers, params=params)
                if response.status_code == 200:
                    data = response.json()
        else:
            logging.error(f"Error: HTTP {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error: {e}")
    return None
