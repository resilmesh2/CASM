CASM_INSERT_QUERY = """
WITH apoc.convert.fromJsonMap($json_string) AS input_, datetime.truncate('second', datetime.fromepochmillis(TIMESTAMP())) as scan_dt
        UNWIND input_.data AS row
        MERGE (ipadd:IP { address: row.ip })
            ON CREATE SET ipadd.tag = ["unknown"]
            SET ipadd.tag = apoc.coll.toSet(ipadd.tag + ["CASM"])
        MERGE (node:Node)-[r1:HAS_ASSIGNED]->(ipadd)
            ON CREATE SET r1.start = scan_dt
        MERGE (host:Host)<-[:IS_A]-(node)
        WITH host, row, ipadd, scan_dt
        MERGE (dn: DomainName { domain_name: row.domain_name})
            ON CREATE SET dn.tag = ["unknown"]
            SET dn.tag = apoc.coll.toSet(["A/AAAA", "CASM"] + dn.tag)
        WITH host, row, dn, ipadd, scan_dt
        OPTIONAL MATCH (dn)<-[r2:RESOLVES_TO]-(ipadd) WHERE r2.end IS NULL
        FOREACH(r IN CASE WHEN r2 IS NULL THEN [r2] ELSE [] END |
            MERGE (dn)<-[:RESOLVES_TO { start:  scan_dt}]-(ipadd)
        )
        WITH host, row, scan_dt
        MERGE (ns: NetworkService {service: row.service, port: row.port, protocol: row.protocol})
            ON CREATE SET ns.tag = ["CASM"]
            SET ns.tag = apoc.coll.toSet(["CASM"] + ns.tag)
        WITH host, row, ns, scan_dt
        MATCH(ns:NetworkService {service: row.service, port: row.port, protocol: row.protocol})
        MATCH (host:Host)<-[IS_A]-(:Node)-[:HAS_ASSIGNED]->(:IP {address: row.ip})
        OPTIONAL MATCH (ns)<-[r3:ON]-(host) WHERE r3.end IS NULL
            FOREACH(r IN CASE WHEN r3 IS NULL THEN [r3] ELSE [] END |
                MERGE (ns)<-[ns_h:ON { start:  scan_dt}]-(host)
                ON CREATE SET ns_h.tag = ["unknown", "CASM"]
            )
        WITH host, row, scan_dt
        UNWIND row.software_versions AS software_version
        MERGE (sv:SoftwareVersion {name: software_version.name})
            ON CREATE SET sv.version = software_version.version
        WITH host, row, scan_dt, software_version
        MATCH (sv:SoftwareVersion {name: software_version.name})
        MATCH (host:Host)<-[IS_A]-(:Node)-[:HAS_ASSIGNED]->(:IP {address: row.ip})
        OPTIONAL MATCH (sv)<-[r4:ON]-(host) WHERE r4.end IS NULL
            FOREACH(r IN CASE WHEN r4 IS NULL THEN [r4] ELSE [] END |
                MERGE (sv)<-[sv_h:ON { start:  scan_dt}]-(host)
                ON CREATE SET sv_h.tag = ["unknown", "CASM"]
            )
        ;
"""
