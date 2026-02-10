UNWIND keys($cve_status) AS cve_id
MATCH (vuln:Vulnerability)-[:REFERS_TO]->(cve:CVE {cve_id: cve_id})
WITH vuln, cve_id, $cve_status[cve_id] AS nuclei_status
WITH vuln, cve_id, nuclei_status,
    CASE
        WHEN vuln.status IS NULL THEN []
        WHEN vuln.status = "estimated"
            OR vuln.status = "confirmed"
            OR vuln.status = "unconfirmed"
            OR vuln.status = "assessed"
            OR vuln.status = "reassessed"
            OR vuln.status = "resolved"
            OR vuln.status = "closed"
            OR vuln.status = "not_found"
        THEN [vuln.status]
        ELSE vuln.status
    END AS current_status
WITH vuln, cve_id, nuclei_status, current_status,
    CASE WHEN size(current_status) > 0 THEN current_status[0] ELSE NULL END AS current_primary,
    [s IN current_status WHERE s IN ["assessed", "reassessed"]] AS secondary_statuses
WITH vuln, cve_id, nuclei_status, current_primary,
    CASE WHEN size(secondary_statuses) > 0 THEN secondary_statuses[0] ELSE NULL END AS current_secondary
WITH vuln, cve_id, current_secondary,
    CASE
        WHEN current_primary IN ["resolved", "closed"] THEN current_primary
        WHEN current_primary = "confirmed" AND nuclei_status IN ["unconfirmed", "not_found"] THEN "closed"
        ELSE nuclei_status
    END AS next_primary
SET vuln.status = CASE
    WHEN next_primary IN ["resolved", "closed"] THEN [next_primary]
    WHEN current_secondary IS NULL THEN [next_primary]
    ELSE [next_primary, current_secondary]
END
RETURN vuln.status AS status, cve_id AS cve_id
