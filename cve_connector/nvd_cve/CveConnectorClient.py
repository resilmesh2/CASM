from cve_connector.nvd_cve.AbsClient import AbstractClient


class CVEConnectorClient(AbstractClient):
    def __init__(self, password: str, bolt="bolt://localhost:7687", user="neo4j", **kwargs) -> None:
        """
        Initializes the CVEConnectorClient with Neo4j connection parameters.

        :param password: Password for Neo4j authentication.
        :param kwargs: Additional arguments for AbstractClient (e.g., bolt, user, driver).
        """
        super().__init__(password=password, bolt=bolt, user=user, **kwargs)

    def cve_exists(self, cve_id: str) -> bool:
        """
        Checks if a CVE exists in the database.

        :param cve_id: CVE identifier (e.g., 'CVE-2021-12345').
        :return: True if the CVE exists, False otherwise.
        """
        with self._driver.session() as session:
            record = session.run("MATCH (cve:CVE) WHERE cve.cve_id = $cve_id RETURN cve.cve_id", cve_id=cve_id)
            return record.single() is not None

    def software_version_exists(self, version: str) -> bool:
        """
        Checks if a software version exists in the database.

        :param version: Software version string (e.g., 'vendor:product:version').
        :return: True if the version exists, False otherwise.
        """
        with self._driver.session() as session:
            record = session.run(
                "MATCH (v:SoftwareVersion) WHERE v.version = $version RETURN v.version", version=version
            )
            return record.single() is not None

    def get_all_software_versions(self) -> list[str]:
        """
        Retrieves all software versions from the Neo4j database.

        :return: List of software version strings.
        """
        with self._driver.session() as session:
            result = session.run(
                "MATCH (v:SoftwareVersion) RETURN v.version AS version, v.cve_timestamp AS cve_timestamp"
            ).data()
            return [
                {"version": record["version"], "cve_timestamp": record.get("cve_timestamp", None)} for record in result
            ]

    def create_new_vulnerability(self, description: str, vulnerability_type: str | None = None) -> None:
        """
        Creates a Vulnerability node in the database.

        :param description: Vulnerability description.
        :param vulnerability_type: Optional vulnerability type.
        :return: None
        """
        self._run_query(
            "CREATE (vul:Vulnerability {description: $description, type: $type})",
            description=description,
            type=vulnerability_type,
        )

    def create_relationship_between_vulnerability_and_software_version(self, description: str, version: str) -> None:
        """
        Creates an IN relationship between a Vulnerability and SoftwareVersion node.

        :param description: Vulnerability description.
        :param version: Software version string.
        :return: None
        """
        self._run_query(
            "MATCH (vul:Vulnerability), (ver:SoftwareVersion) "
            "WHERE vul.description = $description AND ver.version = $version "
            "MERGE (vul)-[:IN]->(ver)",
            description=description,
            version=version,
        )

    def create_cve_from_nvd(
        self,
        cve_id,
        description,
        cwe,
        vector_string_v2,
        access_vector_v2,
        access_complexity_v2,
        authentication_v2,
        confidentiality_impact_v2,
        integrity_impact_v2,
        availability_impact_v2,
        base_score_v2,
        base_severity_v2,
        exploitability_score_v2,
        impact_score_v2,
        ac_insuf_info_v2,
        obtain_all_privilege_v2,
        obtain_user_privilege_v2,
        obtain_other_privilege_v2,
        user_interaction_required_v2,
        vector_string_v30,
        attack_vector_v30,
        attack_complexity_v30,
        privileges_required_v30,
        user_interaction_v30,
        scope_v30,
        confidentiality_impact_v30,
        integrity_impact_v30,
        availability_impact_v30,
        base_score_v30,
        base_severity_v30,
        exploitability_score_v30,
        impact_score_v30,
        vector_string_v31,
        attack_vector_v31,
        attack_complexity_v31,
        privileges_required_v31,
        user_interaction_v31,
        scope_v31,
        confidentiality_impact_v31,
        integrity_impact_v31,
        availability_impact_v31,
        base_score_v31,
        base_severity_v31,
        exploitability_score_v31,
        impact_score_v31,
        vector_string_v40,
        attack_vector_v40,
        attack_complexity_v40,
        attack_requirements_v40,
        privileges_required_v40,
        user_interaction_v40,
        vulnerable_system_confidentiality_v40,
        vulnerable_system_integrity_v40,
        vulnerable_system_availability_v40,
        subsequent_system_confidentiality_v40,
        subsequent_system_integrity_v40,
        subsequent_system_availability_v40,
        exploit_maturity_v40,
        base_score_v40,
        base_severity_v40,
        cpe_type,
        ref_tags,
        published,
        last_modified,
        result_impacts,
    ) -> None:
        """
        Creates a new CVE node along with associated CVSS metrics.

        General CVE parameters:
        :param cve_id: str - ID of the CVE.
        :param description: str - Description of the CVE.
        :param cwe: str - Common Weakness Enumeration (CWE) associated with the CVE.
        :param cpe_type: str - CPE type associated with the CVE.
        :param ref_tags: list or str - Reference tags.
        :param published: str - Publication date of the CVE.
        :param last_modified: str - Last modified date of the CVE.
        :param result_impacts: list - List of impacts determined by the categorizer.

        CVSSv2 Parameters:
        :param vector_string_v2: str - CVSSv2 property Vector String.
        :param access_vector_v2: str - CVSSv2 property Access Vector.
        :param access_complexity_v2: str - CVSSv2 property Access Complexity.
        :param authentication_v2: str - CVSSv2 property Authentication.
        :param confidentiality_impact_v2: str - CVSSv2 property Confidentiality Impact.
        :param integrity_impact_v2: str - CVSSv2 property Integrity Impact.
        :param availability_impact_v2: str - CVSSv2 property Availability Impact.
        :param base_score_v2: float - CVSSv2 property Base Score.
        :param base_severity_v2: str - CVSSv2 property Base Severity.
        :param exploitability_score_v2: float - CVSSv2 property Exploitability Score.
        :param impact_score_v2: float - CVSSv2 property Impact Score.
        :param ac_insuf_info_v2: bool - CVSSv2 property AC Insufficient Info.
        :param obtain_all_privilege_v2: bool - CVSSv2 property Obtain All Privilege flag.
        :param obtain_user_privilege_v2: bool - CVSSv2 property Obtain User Privilege flag.
        :param obtain_other_privilege_v2: bool - CVSSv2 property Obtain Other Privilege flag.
        :param user_interaction_required_v2: bool - CVSSv2 property User Interaction Required flag.

        CVSSv3.0 Parameters:
        :param vector_string_v30: str - CVSSv3.0 property Vector String.
        :param attack_vector_v30: str - CVSSv3.0 property Attack Vector.
        :param attack_complexity_v30: str - CVSSv3.0 property Attack Complexity.
        :param privileges_required_v30: str - CVSSv3.0 property Privileges Required.
        :param user_interaction_v30: str - CVSSv3.0 property User Interaction.
        :param scope_v30: str - CVSSv3.0 property Scope.
        :param confidentiality_impact_v30: str - CVSSv3.0 property Confidentiality Impact.
        :param integrity_impact_v30: str - CVSSv3.0 property Integrity Impact.
        :param availability_impact_v30: str - CVSSv3.0 property Availability Impact.
        :param base_score_v30: float - CVSSv3.0 property Base Score.
        :param base_severity_v30: str - CVSSv3.0 property Base Severity.
        :param exploitability_score_v30: float - CVSSv3.0 property Exploitability Score.
        :param impact_score_v30: float - CVSSv3.0 property Impact Score.

        CVSSv3.1 Parameters:
        :param vector_string_v31: str - CVSSv3.1 property Vector String.
        :param attack_vector_v31: str - CVSSv3.1 property Attack Vector.
        :param attack_complexity_v31: str - CVSSv3.1 property Attack Complexity.
        :param privileges_required_v31: str - CVSSv3.1 property Privileges Required.
        :param user_interaction_v31: str - CVSSv3.1 property User Interaction.
        :param scope_v31: str - CVSSv3.1 property Scope.
        :param confidentiality_impact_v31: str - CVSSv3.1 property Confidentiality Impact.
        :param integrity_impact_v31: str - CVSSv3.1 property Integrity Impact.
        :param availability_impact_v31: str - CVSSv3.1 property Availability Impact.
        :param base_score_v31: float - CVSSv3.1 property Base Score.
        :param base_severity_v31: str - CVSSv3.1 property Base Severity.
        :param exploitability_score_v31: float - CVSSv3.1 property Exploitability Score.
        :param impact_score_v31: float - CVSSv3.1 property Impact Score.

        CVSSv4.0 Parameters:
        :param vector_string_v40: str - CVSSv4.0 property Vector String.
        :param attack_vector_v40: str - CVSSv4.0 property Attack Vector.
        :param attack_complexity_v40: str - CVSSv4.0 property Attack Complexity.
        :param attack_requirements_v40: str - CVSSv4.0 property Attack Requirements.
        :param privileges_required_v40: str - CVSSv4.0 property Privileges Required.
        :param user_interaction_v40: str - CVSSv4.0 property User Interaction.
        :param vulnerable_system_confidentiality_v40: str - CVSSv4.0 property Vulnerable System Confidentiality Impact.
        :param vulnerable_system_integrity_v40: str - CVSSv4.0 property Vulnerable System Integrity Impact.
        :param vulnerable_system_availability_v40: str - CVSSv4.0 property Vulnerable System Availability Impact.
        :param subsequent_system_confidentiality_v40: str - CVSSv4.0 property Subsequent System Confidentiality Impact.
        :param subsequent_system_integrity_v40: str - CVSSv4.0 property Subsequent System Integrity Impact.
        :param subsequent_system_availability_v40: str - CVSSv4.0 property Subsequent System Availability Impact.
        :param exploit_maturity_v40: str - CVSSv4.0 property Exploit Maturity.
        :param base_score_v40: float - CVSSv4.0 property Base Score.
        :param base_severity_v40: str - CVSSv4.0 property Base Severity.

        :return: None
        """
        self._run_query(
            """
    CREATE (cve:CVE {
        cve_id: $cve_id,
        description: $description,
        cwe: $cwe,
        cpe_type: $cpe_type,
        ref_tags: $ref_tags,
        published: $published,
        last_modified: $lastModified,
        result_impacts: $result_impacts
    })
    CREATE (cvss2:CVSSv2 {
        vector_string: $vectorString_v2,
        access_vector: $accessVector_v2,
        access_complexity: $accessComplexity_v2,
        authentication: $authentication_v2,
        confidentiality_impact: $confidentialityImpact_v2,
        integrity_impact: $integrityImpact_v2,
        availability_impact: $availabilityImpact_v2,
        base_score: $baseScore_v2,
        base_severity: $baseSeverity_v2,
        exploitability_score: $exploitabilityScore_v2,
        impact_score: $impactScore_v2,
        ac_insuf_info: $acInsufInfo_v2,
        obtain_all_privilege: $obtainAllPrivilege_v2,
        obtain_user_privilege: $obtainUserPrivilege_v2,
        obtain_other_privilege: $obtainOtherPrivilege_v2,
        user_interaction_required: $userInteractionRequired_v2
    })
    CREATE (cvss30:CVSSv30 {
        vector_string: $vectorString_v30,
        attack_vector: $attackVector_v30,
        attack_complexity: $attackComplexity_v30,
        privileges_required: $privilegesRequired_v30,
        user_interaction: $userInteraction_v30,
        scope: $scope_v30,
        confidentiality_impact: $confidentialityImpact_v30,
        integrity_impact: $integrityImpact_v30,
        availability_impact: $availabilityImpact_v30,
        base_score: $baseScore_v30,
        base_severity: $baseSeverity_v30,
        exploitability_score: $exploitabilityScore_v30,
        impact_score: $impactScore_v30
    })
    CREATE (cvss31:CVSSv31 {
        vector_string: $vectorString_v31,
        attack_vector: $attackVector_v31,
        attack_complexity: $attackComplexity_v31,
        privileges_required: $privilegesRequired_v31,
        user_interaction: $userInteraction_v31,
        scope: $scope_v31,
        confidentiality_impact: $confidentialityImpact_v31,
        integrity_impact: $integrityImpact_v31,
        availability_impact: $availabilityImpact_v31,
        base_score: $baseScore_v31,
        base_severity: $baseSeverity_v31,
        exploitability_score: $exploitabilityScore_v31,
        impact_score: $impactScore_v31
    })
    CREATE (cvss40:CVSSv40 {
        vector_string: $vectorString_v40,
        attack_vector: $attackVector_v40,
        attack_complexity: $attackComplexity_v40,
        attack_requirements: $attackRequirements_v40,
        privileges_required: $privilegesRequired_v40,
        user_interaction: $userInteraction_v40,
        vulnerable_system_confidentiality: $vulnerableSystemConfidentiality_v40,
        vulnerable_system_integrity: $vulnerableSystemIntegrity_v40,
        vulnerable_system_availability: $vulnerableSystemAvailability_v40,
        subsequent_system_confidentiality: $subsequentSystemConfidentiality_v40,
        subsequent_system_integrity: $subsequentSystemIntegrity_v40,
        subsequent_system_availability: $subsequentSystemAvailability_v40,
        exploit_maturity: $exploitMaturity_v40,
        base_score: $baseScore_v40,
        base_severity: $baseSeverity_v40
    })
    CREATE (cve)-[:HAS_CVSS_v2]->(cvss2)
    CREATE (cve)-[:HAS_CVSS_v30]->(cvss30)
    CREATE (cve)-[:HAS_CVSS_v31]->(cvss31)
    CREATE (cve)-[:HAS_CVSS_v40]->(cvss40)
            """,
            cve_id=cve_id,
            description=description,
            cwe=cwe,
            vectorString_v2=vector_string_v2,
            accessVector_v2=access_vector_v2,
            accessComplexity_v2=access_complexity_v2,
            authentication_v2=authentication_v2,
            confidentialityImpact_v2=confidentiality_impact_v2,
            integrityImpact_v2=integrity_impact_v2,
            availabilityImpact_v2=availability_impact_v2,
            baseScore_v2=base_score_v2,
            baseSeverity_v2=base_severity_v2,
            exploitabilityScore_v2=exploitability_score_v2,
            impactScore_v2=impact_score_v2,
            acInsufInfo_v2=ac_insuf_info_v2,
            obtainAllPrivilege_v2=obtain_all_privilege_v2,
            obtainUserPrivilege_v2=obtain_user_privilege_v2,
            obtainOtherPrivilege_v2=obtain_other_privilege_v2,
            userInteractionRequired_v2=user_interaction_required_v2,
            vectorString_v30=vector_string_v30,
            attackVector_v30=attack_vector_v30,
            attackComplexity_v30=attack_complexity_v30,
            privilegesRequired_v30=privileges_required_v30,
            userInteraction_v30=user_interaction_v30,
            scope_v30=scope_v30,
            confidentialityImpact_v30=confidentiality_impact_v30,
            integrityImpact_v30=integrity_impact_v30,
            availabilityImpact_v30=availability_impact_v30,
            baseScore_v30=base_score_v30,
            baseSeverity_v30=base_severity_v30,
            exploitabilityScore_v30=exploitability_score_v30,
            impactScore_v30=impact_score_v30,
            vectorString_v31=vector_string_v31,
            attackVector_v31=attack_vector_v31,
            attackComplexity_v31=attack_complexity_v31,
            privilegesRequired_v31=privileges_required_v31,
            userInteraction_v31=user_interaction_v31,
            scope_v31=scope_v31,
            confidentialityImpact_v31=confidentiality_impact_v31,
            integrityImpact_v31=integrity_impact_v31,
            availabilityImpact_v31=availability_impact_v31,
            baseScore_v31=base_score_v31,
            baseSeverity_v31=base_severity_v31,
            exploitabilityScore_v31=exploitability_score_v31,
            impactScore_v31=impact_score_v31,
            vectorString_v40=vector_string_v40,
            attackVector_v40=attack_vector_v40,
            attackComplexity_v40=attack_complexity_v40,
            attackRequirements_v40=attack_requirements_v40,
            privilegesRequired_v40=privileges_required_v40,
            userInteraction_v40=user_interaction_v40,
            vulnerableSystemConfidentiality_v40=vulnerable_system_confidentiality_v40,
            vulnerableSystemIntegrity_v40=vulnerable_system_integrity_v40,
            vulnerableSystemAvailability_v40=vulnerable_system_availability_v40,
            subsequentSystemConfidentiality_v40=subsequent_system_confidentiality_v40,
            subsequentSystemIntegrity_v40=subsequent_system_integrity_v40,
            subsequentSystemAvailability_v40=subsequent_system_availability_v40,
            exploitMaturity_v40=exploit_maturity_v40,
            baseScore_v40=base_score_v40,
            baseSeverity_v40=base_severity_v40,
            cpe_type=cpe_type,
            ref_tags=ref_tags,
            published=published,
            lastModified=last_modified,
            result_impacts=result_impacts,
        )

    def create_relationship_between_cve_and_vulnerability(self, cve_id: str, vulnerability_description: str) -> None:
        """
        Creates a REFERS_TO relationship between a CVE and Vulnerability node.

        :param cve_id: CVE identifier.
        :param vulnerability_description: Vulnerability description.
        :return: None
        """
        self._run_query(
            "MATCH (cve:CVE), (vul:Vulnerability) "
            "WHERE cve.cve_id = $cve_id AND vul.description = $description "
            "MERGE (vul)-[:REFERS_TO]->(cve)",
            cve_id=cve_id,
            description=vulnerability_description,
        )

    def update_cve_from_nvd(
        self,
        cve_id,
        description,
        cwe,
        vector_string_v2,
        access_vector_v2,
        access_complexity_v2,
        authentication_v2,
        confidentiality_impact_v2,
        integrity_impact_v2,
        availability_impact_v2,
        base_score_v2,
        base_severity_v2,
        exploitability_score_v2,
        impact_score_v2,
        ac_insuf_info_v2,
        obtain_all_privilege_v2,
        obtain_user_privilege_v2,
        obtain_other_privilege_v2,
        user_interaction_required_v2,
        vector_string_v30,
        attack_vector_v30,
        attack_complexity_v30,
        privileges_required_v30,
        user_interaction_v30,
        scope_v30,
        confidentiality_impact_v30,
        integrity_impact_v30,
        availability_impact_v30,
        base_score_v30,
        base_severity_v30,
        exploitability_score_v30,
        impact_score_v30,
        vector_string_v31,
        attack_vector_v31,
        attack_complexity_v31,
        privileges_required_v31,
        user_interaction_v31,
        scope_v31,
        confidentiality_impact_v31,
        integrity_impact_v31,
        availability_impact_v31,
        base_score_v31,
        base_severity_v31,
        exploitability_score_v31,
        impact_score_v31,
        vector_string_v40,
        attack_vector_v40,
        attack_complexity_v40,
        attack_requirements_v40,
        privileges_required_v40,
        user_interaction_v40,
        vulnerable_system_confidentiality_v40,
        vulnerable_system_integrity_v40,
        vulnerable_system_availability_v40,
        subsequent_system_confidentiality_v40,
        subsequent_system_integrity_v40,
        subsequent_system_availability_v40,
        exploit_maturity_v40,
        base_score_v40,
        base_severity_v40,
        cpe_type,
        ref_tags,
        published,
        last_modified,
        result_impacts,
    ) -> None:
        """
        Updates an existing CVE node in the database with new details, including associated CVSS metrics.

        General CVE parameters:
        :param cve_id: str - The CVE identifier.
        :param description: str - The updated description of the CVE.
        :param cwe: str - The updated Common Weakness Enumeration (CWE).
        :param cpe_type: str - The updated CPE type.
        :param ref_tags: list or str - Updated reference tags.
        :param published: str - Updated publication date.
        :param last_modified: str - Updated last modified date.
        :param result_impacts: list - Updated list of impacts.

        CVSSv2 Parameters:
        :param vector_string_v2: str - Updated CVSSv2 Vector String.
        :param access_vector_v2: str - Updated CVSSv2 Access Vector.
        :param access_complexity_v2: str - Updated CVSSv2 Access Complexity.
        :param authentication_v2: str - Updated CVSSv2 Authentication.
        :param confidentiality_impact_v2: str - Updated CVSSv2 Confidentiality Impact.
        :param integrity_impact_v2: str - Updated CVSSv2 Integrity Impact.
        :param availability_impact_v2: str - Updated CVSSv2 Availability Impact.
        :param base_score_v2: float - Updated CVSSv2 Base Score.
        :param base_severity_v2: str - Updated CVSSv2 Base Severity.
        :param exploitability_score_v2: float - Updated CVSSv2 Exploitability Score.
        :param impact_score_v2: float - Updated CVSSv2 Impact Score.
        :param ac_insuf_info_v2: bool - Updated CVSSv2 AC Insufficient Info flag.
        :param obtain_all_privilege_v2: bool - Updated CVSSv2 Obtain All Privilege flag.
        :param obtain_user_privilege_v2: bool - Updated CVSSv2 Obtain User Privilege flag.
        :param obtain_other_privilege_v2: bool - Updated CVSSv2 Obtain Other Privilege flag.
        :param user_interaction_required_v2: bool - Updated CVSSv2 User Interaction Required flag.

        CVSSv3.0 Parameters:
        :param vector_string_v30: str - Updated CVSSv3.0 Vector String.
        :param attack_vector_v30: str - Updated CVSSv3.0 Attack Vector.
        :param attack_complexity_v30: str - Updated CVSSv3.0 Attack Complexity.
        :param privileges_required_v30: str - Updated CVSSv3.0 Privileges Required.
        :param user_interaction_v30: str - Updated CVSSv3.0 User Interaction.
        :param scope_v30: str - Updated CVSSv3.0 Scope.
        :param confidentiality_impact_v30: str - Updated CVSSv3.0 Confidentiality Impact.
        :param integrity_impact_v30: str - Updated CVSSv3.0 Integrity Impact.
        :param availability_impact_v30: str - Updated CVSSv3.0 Availability Impact.
        :param base_score_v30: float - Updated CVSSv3.0 Base Score.
        :param base_severity_v30: str - Updated CVSSv3.0 Base Severity.
        :param exploitability_score_v30: float - Updated CVSSv3.0 Exploitability Score.
        :param impact_score_v30: float - Updated CVSSv3.0 Impact Score.

        CVSSv3.1 Parameters:
        :param vector_string_v31: str - Updated CVSSv3.1 Vector String.
        :param attack_vector_v31: str - Updated CVSSv3.1 Attack Vector.
        :param attack_complexity_v31: str - Updated CVSSv3.1 Attack Complexity.
        :param privileges_required_v31: str - Updated CVSSv3.1 Privileges Required.
        :param user_interaction_v31: str - Updated CVSSv3.1 User Interaction.
        :param scope_v31: str - Updated CVSSv3.1 Scope.
        :param confidentiality_impact_v31: str - Updated CVSSv3.1 Confidentiality Impact.
        :param integrity_impact_v31: str - Updated CVSSv3.1 Integrity Impact.
        :param availability_impact_v31: str - Updated CVSSv3.1 Availability Impact.
        :param base_score_v31: float - Updated CVSSv3.1 Base Score.
        :param base_severity_v31: str - Updated CVSSv3.1 Base Severity.
        :param exploitability_score_v31: float - Updated CVSSv3.1 Exploitability Score.
        :param impact_score_v31: float - Updated CVSSv3.1 Impact Score.

        CVSSv4.0 Parameters:
        :param vector_string_v40: str - Updated CVSSv4.0 Vector String.
        :param attack_vector_v40: str - Updated CVSSv4.0 Attack Vector.
        :param attack_complexity_v40: str - Updated CVSSv4.0 Attack Complexity.
        :param attack_requirements_v40: str - Updated CVSSv4.0 Attack Requirements.
        :param privileges_required_v40: str - Updated CVSSv4.0 Privileges Required.
        :param user_interaction_v40: str - Updated CVSSv4.0 User Interaction.
        :param vulnerable_system_confidentiality_v40: str - Updated CVSSv4.0 Vulnerable System Confidentiality Impact.
        :param vulnerable_system_integrity_v40: str - Updated CVSSv4.0 Vulnerable System Integrity Impact.
        :param vulnerable_system_availability_v40: str - Updated CVSSv4.0 Vulnerable System Availability Impact.
        :param subsequent_system_confidentiality_v40: str - Updated CVSSv4.0 Subsequent System Confidentiality Impact.
        :param subsequent_system_integrity_v40: str - Updated CVSSv4.0 Subsequent System Integrity Impact.
        :param subsequent_system_availability_v40: str - Updated CVSSv4.0 Subsequent System Availability Impact.
        :param exploit_maturity_v40: str - Updated CVSSv4.0 Exploit Maturity.
        :param base_score_v40: float - Updated CVSSv4.0 Base Score.
        :param base_severity_v40: str - Updated CVSSv4.0 Base Severity.

        :return: None
        """
        self._run_query(
            """
    MATCH (cve:CVE {cve_id: $cve_id})
    SET cve.description = $description,
        cve.cwe = $cwe,
        cve.cpe_type = $cpe_type,
        cve.ref_tags = $ref_tags,
        cve.published = $published,
        cve.last_modified = $lastModified,
        cve.result_impacts = $result_impacts
    WITH cve
    OPTIONAL MATCH (cve)-[r2:HAS_CVSS_v2]->(cvss2:CVSSv2)
    SET cvss2 = {
        vector_string: $vectorString_v2,
        access_vector: $accessVector_v2,
        access_complexity: $accessComplexity_v2,
        authentication: $authentication_v2,
        confidentiality_impact: $confidentialityImpact_v2,
        integrity_impact: $integrityImpact_v2,
        availability_impact: $availabilityImpact_v2,
        base_score: $baseScore_v2,
        base_severity: $baseSeverity_v2,
        exploitability_score: $exploitabilityScore_v2,
        impact_score: $impactScore_v2,
        ac_insuf_info: $acInsufInfo_v2,
        obtain_all_privilege: $obtainAllPrivilege_v2,
        obtain_user_privilege: $obtainUserPrivilege_v2,
        obtain_other_privilege: $obtainOtherPrivilege_v2,
        user_interaction_required: $userInteractionRequired_v2
    }
    WITH cve
    OPTIONAL MATCH (cve)-[r30:HAS_CVSS_v30]->(cvss30:CVSSv30)
    SET cvss30 = {
        vector_string: $vectorString_v30,
        attack_vector: $attackVector_v30,
        attack_complexity: $attackComplexity_v30,
        privileges_required: $privilegesRequired_v30,
        user_interaction: $userInteraction_v30,
        scope: $scope_v30,
        confidentiality_impact: $confidentialityImpact_v30,
        integrity_impact: $integrityImpact_v30,
        availability_impact: $availabilityImpact_v30,
        base_score: $baseScore_v30,
        base_severity: $baseSeverity_v30,
        exploitability_score: $exploitabilityScore_v30,
        impact_score: $impactScore_v30
    }
    WITH cve
    OPTIONAL MATCH (cve)-[r31:HAS_CVSS_v31]->(cvss31:CVSSv31)
    SET cvss31 = {
        vector_string: $vectorString_v31,
        attack_vector: $attackVector_v31,
        attack_complexity: $attackComplexity_v31,
        privileges_required: $privilegesRequired_v31,
        user_interaction: $userInteraction_v31,
        scope: $scope_v31,
        confidentiality_impact: $confidentialityImpact_v31,
        integrity_impact: $integrityImpact_v31,
        availability_impact: $availabilityImpact_v31,
        base_score: $baseScore_v31,
        base_severity: $baseSeverity_v31,
        exploitability_score: $exploitabilityScore_v31,
        impact_score: $impactScore_v31
    }
    WITH cve
    OPTIONAL MATCH (cve)-[r40:HAS_CVSS_v40]->(cvss40:CVSSv40)
    SET cvss40 = {
        vector_string: $vectorString_v40,
        attack_vector: $attackVector_v40,
        attack_complexity: $attackComplexity_v40,
        attack_requirements: $attackRequirements_v40,
        privileges_required: $privilegesRequired_v40,
        user_interaction: $userInteraction_v40,
        vulnerable_system_confidentiality: $vulnerableSystemConfidentiality_v40,
        vulnerable_system_integrity: $vulnerableSystemIntegrity_v40,
        vulnerable_system_availability: $vulnerableSystemAvailability_v40,
        subsequent_system_confidentiality: $subsequentSystemConfidentiality_v40,
        subsequent_system_integrity: $subsequentSystemIntegrity_v40,
        subsequent_system_availability: $subsequentSystemAvailability_v40,
        exploit_maturity: $exploitMaturity_v40,
        base_score: $baseScore_v40,
        base_severity: $baseSeverity_v40
    }
            """,
            cve_id=cve_id,
            description=description,
            cwe=cwe,
            vectorString_v2=vector_string_v2,
            accessVector_v2=access_vector_v2,
            accessComplexity_v2=access_complexity_v2,
            authentication_v2=authentication_v2,
            confidentialityImpact_v2=confidentiality_impact_v2,
            integrityImpact_v2=integrity_impact_v2,
            availabilityImpact_v2=availability_impact_v2,
            baseScore_v2=base_score_v2,
            baseSeverity_v2=base_severity_v2,
            exploitabilityScore_v2=exploitability_score_v2,
            impactScore_v2=impact_score_v2,
            acInsufInfo_v2=ac_insuf_info_v2,
            obtainAllPrivilege_v2=obtain_all_privilege_v2,
            obtainUserPrivilege_v2=obtain_user_privilege_v2,
            obtainOtherPrivilege_v2=obtain_other_privilege_v2,
            userInteractionRequired_v2=user_interaction_required_v2,
            vectorString_v30=vector_string_v30,
            attackVector_v30=attack_vector_v30,
            attackComplexity_v30=attack_complexity_v30,
            privilegesRequired_v30=privileges_required_v30,
            userInteraction_v30=user_interaction_v30,
            scope_v30=scope_v30,
            confidentialityImpact_v30=confidentiality_impact_v30,
            integrityImpact_v30=integrity_impact_v30,
            availabilityImpact_v30=availability_impact_v30,
            baseScore_v30=base_score_v30,
            baseSeverity_v30=base_severity_v30,
            exploitabilityScore_v30=exploitability_score_v30,
            impactScore_v30=impact_score_v30,
            vectorString_v31=vector_string_v31,
            attackVector_v31=attack_vector_v31,
            attackComplexity_v31=attack_complexity_v31,
            privilegesRequired_v31=privileges_required_v31,
            userInteraction_v31=user_interaction_v31,
            scope_v31=scope_v31,
            confidentialityImpact_v31=confidentiality_impact_v31,
            integrityImpact_v31=integrity_impact_v31,
            availabilityImpact_v31=availability_impact_v31,
            baseScore_v31=base_score_v31,
            baseSeverity_v31=base_severity_v31,
            exploitabilityScore_v31=exploitability_score_v31,
            impactScore_v31=impact_score_v31,
            vectorString_v40=vector_string_v40,
            attackVector_v40=attack_vector_v40,
            attackComplexity_v40=attack_complexity_v40,
            attackRequirements_v40=attack_requirements_v40,
            privilegesRequired_v40=privileges_required_v40,
            userInteraction_v40=user_interaction_v40,
            vulnerableSystemConfidentiality_v40=vulnerable_system_confidentiality_v40,
            vulnerableSystemIntegrity_v40=vulnerable_system_integrity_v40,
            vulnerableSystemAvailability_v40=vulnerable_system_availability_v40,
            subsequentSystemConfidentiality_v40=subsequent_system_confidentiality_v40,
            subsequentSystemIntegrity_v40=subsequent_system_integrity_v40,
            subsequentSystemAvailability_v40=subsequent_system_availability_v40,
            exploitMaturity_v40=exploit_maturity_v40,
            baseScore_v40=base_score_v40,
            baseSeverity_v40=base_severity_v40,
            cpe_type=cpe_type,
            ref_tags=ref_tags,
            published=published,
            lastModified=last_modified,
            result_impacts=result_impacts,
        )

    def get_versions_of_product(self, vendor_and_product: str) -> list[str]:
        """
        Retrieves software versions for a given vendor and product.

        :param vendor_and_product: Vendor and product string (e.g., 'vendor:product').
        :return: List of dictionaries with version details.
        """
        product_string = vendor_and_product + ":"
        with self._driver.session() as session:
            return session.run(
                "MATCH (s:SoftwareVersion) WHERE s.version STARTS WITH $product_string "
                "RETURN {version: s.version} AS software",
                product_string=product_string,
            ).data()

    def update_timestamp_of_software_version(self, version: str, cve_timestamp: str) -> None:
        """
        Creates or updates a timestamp for an existing software version.
        :param version: Software version that will be updated.
        :param cve_timestamp: Timestamp of the last retrieval of CVEs from the NVD.
        :return: None
        """
        with self._driver.session() as session:
            session.run(
                "MATCH (s:SoftwareVersion) WHERE s.version = $version SET s.cve_timestamp = $cve_timestamp",
                version=version,
                cve_timestamp=cve_timestamp,
            )
