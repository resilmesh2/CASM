# CVE connector

CVE connector obtains data about CVEs from the National vulnerability Database (NVD)

##### Subcomponent `nvd_cve`
This part of CVE connector is responsible for download of CVEs from the NVD's REST API, their parsing, assigning 
predicted impact and storing to the database.

1. Folder `categorization` contains implementation of categorization algorithm split among several modules.
2. Module `cve_parser.py` contains parser of CVE data provided by the NVD.
3. Module `toneo4j.py` contains functionality which adds parsed data to Neo4j database according to CPEs present in the database.
4. Module `cve_client.py` contains functionality which gets CVE data provided by the NVD API.
5. Module `vulnerability.py` contains CVE class.

## Required packages/versions

At least `Python3.13`. 

Required packages are be specified in `setup.py` and they will be installed when one of following installation methods is used.
The implementation was prepared for Neo4j database version 5.24.0

## Usage

### Install

You can install CVE connector with pip from local directory via:

```bash
$ pip install . -r requirements.txt
```

### Running

CVE connector can be run locally. You need to obtain your NVD REST API key from https://nvd.nist.gov/developers/request-an-api-key.
We used `name and surname` as `organization name` and `personal use / not listed` as `organization type`.
The API KEY should be filled into [config.py](cve_connector/cve_config.py) as api_key.

You need a running instance of Neo4j at Neo4j's standard bolt `bolt://localhost:7687`.
Your database should contain some SoftwareVersions, e.g.,

```neo4j
neo4j$ CREATE (e:SoftwareVersion {version: 'huawei:fusioncompute:8.0.0'})
```

You can also use a Neo4j dump from https://github.com/Resilmesh-EU/datasets/blob/main/CRUSOE%20Datasets/cyber-czech-neo4j-Jan-30-2025-16-36-11.dump,
but you need to handle or delete old CVEs with old names of properties. This version of CVE connector
had to add suffixes of CVSS versions to properties to cope with multiple CVSS versions. List of current
properties is available in schema.graphql in ISIM's GraphQL API and will be soon updated in the data model.

Example use of CVE connector:

```python
api_key="YOUR API KEY"
neo4j_password="YOUR NEO4J PASSWORD"

from cve_connector.nvd_cve.toneo4j import move_cve_data_to_neo4j, get_software_versions_from_neo4j
from cve_connector.nvd_cve.cve_parser import parse_vulnerabilities
from cve_connector.nvd_cve.cve_client import search_cve_by_version

versions = get_software_versions_from_neo4j(neo4j_password)
for version in versions:
    for part in ['a', 'o', 'h']:
        cve_data = None
        while cve_data is None:
            cve_data = search_cve_by_version(version=version, part=part, api_key=api_key)
            if cve_data is None:
                time.sleep(1)
        parsed_data = parse_vulnerabilities(data=cve_data)
        move_cve_data_to_neo4j(parsed_data, neo4j_password)
```

You can increase count of days to obtain older vulnerabilities, but it can take very long time to store them.

Classification of impacts is experimental and will be tested in the future.

CVE connector was based on a work by Adam Helc from https://is.muni.cz/th/a4dub/?lang=en.
