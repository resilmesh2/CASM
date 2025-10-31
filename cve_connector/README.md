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

## NVD API KEY
You need to obtain your NVD REST API key from https://nvd.nist.gov/developers/request-an-api-key.
We used `name and surname` as `organization name` and `personal use / not listed` as `organization type`.
The API KEY should be filled into configuration files in [config](../config/config.yaml) and 
[docker](../docker/config.yaml) folders for cve_connector as nvd_api_key. 
If you encounter any issues, you can try to fill the value also in [config.py](../config.py) 
as nvd_api_key as a string, i.e., `"<api_key_value>"`.

## Usage

CVE connector can be run locally. The easiest way to use CVE connector is to use [compose.yml](../compose.yml) and 
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
from cve_connector.cve_temporal import cve_version
from datetime import datetime

workflow_start = datetime.now().isoformat()
neo4j_bolt = "bolt://localhost:7687"
neo4j_user = "neo4j"
neo4j_password = "<your_password>"
nvd_api_key = "<your_api_key>"
cve_version(workflow_start, neo4j_password, neo4j_bolt, neo4j_user, nvd_api_key)
```

Finally, deactivate the virtual environment with:

```shell
deactivate
```

Classification of impacts is experimental and will be tested in the future.

CVE connector was based on a work by Adam Helc from https://is.muni.cz/th/a4dub/?lang=en.
