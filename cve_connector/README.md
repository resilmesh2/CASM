# CVE connector

CVE connector obtains data about CVEs from the National Vulnerability Database (NVD).

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

Required packages are specified in `setup.py` and they will be installed when one of following installation methods is used.
The implementation was prepared for Neo4j database version 5.24.0

## Usage

CVE connector can be run locally. You need to obtain your NVD REST API key from https://nvd.nist.gov/developers/request-an-api-key.
We used `name and surname` as `organization name` and `personal use / not listed` as `organization type`.
The API KEY should be filled into [config.py](cve_connector/cve_config.py) as api_key as a string, i.e., `"<api_key_value>"`.

The easiest way to use CVE connector is to use [compose.yml](../compose.yml) and 
instructions from the [README.md](../README.md) for the whole CASM 
repository. The CVE connector is created as one of containers and its workflows are added to temporal automatically. 
They are executed each two hours by default.

It is possible to execute download of CVEs directly but the recommended way is to use the compose file.
In the case of direct execution, you need a running instance of Neo4j at Neo4j's standard bolt `bolt://localhost:7687`.
Your database should contain some SoftwareVersions, e.g.,

```neo4j
neo4j$ CREATE (e:SoftwareVersion {version: 'huawei:fusioncompute:8.0.0'})
```

You can also use a Neo4j dump from https://github.com/Resilmesh-EU/datasets/blob/main/CRUSOE%20Datasets/cyber-czech-neo4j-Jan-30-2025-16-36-11.dump,
but you need to handle or delete old CVEs with old names of properties. This version of CVE connector
had to add CVSS versions as separate vertices to cope with multiple CVSS versions. List of current
properties is available in schema.graphql in ISIM's GraphQL API and in the data model.

Example use of CVE connector requires to set a virtual environment in the `CASM/cve_connector` folder.
For example, you can use these commands:

```shell
python3 -m venv ./venv
source venv/bin/activate
pip install -r cve_connector/requirements.txt
python3 
```

Consequently, execute the following commands from `python` console: 

```python
api_key="YOUR API KEY"
neo4j_password="YOUR NEO4J PASSWORD"

from cve_connector.nvd_cve.toneo4j import move_cve_data_to_neo4j, get_software_versions_from_neo4j
from cve_connector.nvd_cve.cve_parser import parse_vulnerabilities
from cve_connector.nvd_cve.cve_client import search_cve_by_version

versions_and_timestamps = get_software_versions_from_neo4j(neo4j_password)
for version_item in versions_and_timestamps:
    version = version_item['version']
    for part in ['a', 'o', 'h']:
        cve_data = None
        raw_data = search_cve_by_version(version=version, part=part, api_key=api_key)
        if "vulnerabilities" in raw_data:
            cve_data = [vuln["cve"] for vuln in raw_data.get("vulnerabilities", [])]
            parsed_data = parse_vulnerabilities(data=cve_data)
            move_cve_data_to_neo4j(parsed_data, neo4j_password)
```

Finally, deactivate the virtual environment with:

```shell
deactivate
```

Classification of impacts is experimental and will be tested in the future.

CVE connector was based on a work by Adam Helc from https://is.muni.cz/th/a4dub/?lang=en.
