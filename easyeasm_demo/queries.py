CASM_INSERT_QUERY = """
WITH apoc.convert.fromJsonMap($json_string) AS input_, datetime.truncate('second', datetime.fromepochmillis(TIMESTAMP())) as scan_dt
        UNWIND input_.data AS row
        MERGE (ipadd:IP { address: row.ip })
        MERGE (node:Node)-[r1:HAS_ASSIGNED]->(ipadd)
            ON CREATE SET r1.start = scan_dt
        MERGE (host:Host)<-[:IS_A]-(node)
        WITH host, row, ipadd, scan_dt
        MERGE (dn: DomainName { domain_name: row.domain_name})
            ON CREATE SET dn.tag = ['A/AAAA']
            ON MATCH SET dn.tag = [tag in dn.tag where tag <> 'A/AAAA'] + ['A/AAAA']
        WITH host, row, dn, ipadd, scan_dt
        OPTIONAL MATCH (dn)<-[r2:RESOLVES_TO]-(ipadd) WHERE r2.end IS NULL
        FOREACH(r IN CASE WHEN r2 IS NULL THEN [r2] ELSE [] END |
            MERGE (dn)<-[:RESOLVES_TO { start:  scan_dt}]-(ipadd)
        )
        WITH host, row, scan_dt
        MERGE (ns: NetworkService {service: row.service, port: row.port, protocol: row.protocol})
            ON CREATE SET ns.tag = ['CASM']
            ON MATCH SET ns.tag = [tag in ns.tag where tag <> 'CASM'] + ['CASM']
        WITH host, row, ns, scan_dt
        MATCH(ns:NetworkService {service: row.service, port: row.port, protocol: row.protocol})
        MATCH (host:Host)<-[IS_A]-(:Node)-[:HAS_ASSIGNED]->(:IP {address: row.ip})
        OPTIONAL MATCH (ns)<-[r3:ON]-(host) WHERE r3.end IS NULL
            FOREACH(r IN CASE WHEN r3 IS NULL THEN [r3] ELSE [] END |
                MERGE (ns)<-[:ON { start:  scan_dt}]-(host)
            )
        ;
"""
