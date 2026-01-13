UNWIND keys($cve_status) AS cve_id
MATCH (vuln:Vulnerability)-[:REFERS_TO]->(cve:CVE {cve_id: cve_id})
SET vuln.status = $cve_status[cve_id]
RETURN vuln.status AS status, cve.cve_id AS cve_id