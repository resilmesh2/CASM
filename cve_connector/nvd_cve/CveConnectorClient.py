import logging
from cve_connector.nvd_cve.AbsClient import AbstractClient


class CVEConnectorClient(AbstractClient):
    def __init__(self, password, **kwargs):
        super().__init__(password=password, **kwargs)

    def cve_exists(self, cve_id):
        """
        Checks whether CVE with the specified ID exists in the database.
        :param cve_id: id of CVE
        :return: True if such CVE exists in the database
        """
        with (self._driver.session()) as session:
            record = session.run("MATCH (cve:CVE) \
                                  WHERE cve.cve_id = $cve_id \
                                  RETURN cve.cve_id",
                                 **{'cve_id': cve_id})
            return record.single() is not None

    def software_version_exists(self, version):
        """
        Checks whether specified software version exists in the database
        :param version: version of software
        :return: TRue if such version exists in the database
        """
        with (self._driver.session()) as session:
            record = session.run("MATCH (v:SoftwareVersion) \
                                      WHERE v.version = $version \
                                      RETURN v.version",
                                     **{'version': version})
            return record.single() is not None

    def create_new_vulnerability(self, description, vulnerability_type=None):
        """
        Create node of type Vulnerability
        :param description: description of vulnerability
        :param vulnerability_type: type of vulnerability
        :return:
        """
        self._run_query("CREATE (vul:Vulnerability {description: $description, type: $type})",
                        **{'description': description, 'type': vulnerability_type})

    def create_relationship_between_vulnerability_and_software_version(self, description, version):
        """
        Creates relationship of type :IN between vulnerability and version of software
        :param description: description of vulnerability
        :param version: version of software
        :return:
        """
        self._run_query("MATCH (vul:Vulnerability), (ver:SoftwareVersion) \
                         WHERE vul.description = $description AND ver.version = $version \
                         MERGE (vul)-[:IN]->(ver)",
                        **{'description': description, 'version': version})

    def create_cve_from_nvd(self, 
                            cve_id, 
                            description, 
                            cwe,
                            vectorString_v2,
                            accessVector_v2,
                            accessComplexity_v2,
                            authentication_v2,
                            confidentialityImpact_v2,
                            integrityImpact_v2,
                            availabilityImpact_v2,
                            baseScore_v2,
                            baseSeverity_v2,
                            exploitabilityScore_v2,
                            impactScore_v2,
                            acInsufInfo_v2,
                            obtainAllPrivilege_v2,
                            obtainUserPrivilege_v2,
                            obtainOtherPrivilege_v2,
                            userInteractionRequired_v2,
                            vectorString_v30,
                            attackVector_v30,
                            attackComplexity_v30,
                            privilegesRequired_v30,
                            userInteraction_v30,
                            scope_v30,
                            confidentialityImpact_v30,
                            integrityImpact_v30,
                            availabilityImpact_v30,
                            baseScore_v30,
                            baseSeverity_v30,
                            exploitabilityScore_v30,
                            impactScore_v30,
                            vectorString_v31,
                            attackVector_v31,
                            attackComplexity_v31,
                            privilegesRequired_v31,
                            userInteraction_v31,
                            scope_v31,
                            confidentialityImpact_v31,
                            integrityImpact_v31,
                            availabilityImpact_v31,
                            baseScore_v31,
                            baseSeverity_v31,
                            exploitabilityScore_v31,
                            impactScore_v31,
                            vectorString_v40,
                            attackVector_v40,
                            attackComplexity_v40,
                            attackRequirements_v40,
                            privilegesRequired_v40,
                            userInteraction_v40,
                            vulnerableSystemConfidentiality_v40,
                            vulnerableSystemIntegrity_v40,
                            vulnerableSystemAvailability_v40,
                            subsequentSystemConfidentiality_v40,
                            subsequentSystemIntegrity_v40,
                            subsequentSystemAvailability_v40,
                            baseScore_v40,
                            baseSeverity_v40,
                            cpe_type,
                            ref_tags,
                            published,
                            lastModified,
                            result_impacts):
        """
        Creates new node of type CVE

        :param cve_id: ID of the CVE
        :param description: Description of the CVE
        :param cwe: Common Weakness Enumeration (CWE) associated with the CVE
        :param vectorString_v2: CVSSv2 property Vector String
        :param accessVector_v2: CVSSv2 property Access Vector
        :param accessComplexity_v2: CVSSv2 property Access Complexity
        :param authentication_v2: CVSSv2 property Authentication
        :param confidentialityImpact_v2: CVSSv2 property Confidentiality Impact
        :param integrityImpact_v2: CVSSv2 property Integrity Impact
        :param availabilityImpact_v2: CVSSv2 property Availability Impact
        :param baseScore_v2: CVSSv2 property Base Score
        :param baseSeverity_v2: CVSSv2 property Base Severity
        :param exploitabilityScore_v2: CVSSv2 property Exploitability Score
        :param impactScore_v2: CVSSv2 property Impact Score
        :param acInsufInfo_v2: CVSSv2 property AC Insufficient Info
        :param obtainAllPrivilege_v2: CVSSv2 property Obtain All Privilege flag
        :param obtainUserPrivilege_v2: CVSSv2 property Obtain User Privilege flag
        :param obtainOtherPrivilege_v2: CVSSv2 property Obtain Other Privilege flag
        :param userInteractionRequired_v2: CVSSv2 property User Interaction Required flag
        :param vectorString_v30: CVSSv3.0 property Vector String
        :param attackVector_v30: CVSSv3.0 property Attack Vector
        :param attackComplexity_v30: CVSSv3.0 property Attack Complexity
        :param privilegesRequired_v30: CVSSv3.0 property Privileges Required
        :param userInteraction_v30: CVSSv3.0 property User Interaction
        :param scope_v30: CVSSv3.0 property Scope
        :param confidentialityImpact_v30: CVSSv3.0 property Confidentiality Impact
        :param integrityImpact_v30: CVSSv3.0 property Integrity Impact
        :param availabilityImpact_v30: CVSSv3.0 property Availability Impact
        :param baseScore_v30: CVSSv3.0 property Base Score
        :param baseSeverity_v30: CVSSv3.0 property Base Severity
        :param exploitabilityScore_v30: CVSSv3.0 property Exploitability Score
        :param impactScore_v30: CVSSv3.0 property Impact Score
        :param vectorString_v31: CVSSv3.1 property Vector String
        :param attackVector_v31: CVSSv3.1 property Attack Vector
        :param attackComplexity_v31: CVSSv3.1 property Attack Complexity
        :param privilegesRequired_v31: CVSSv3.1 property Privileges Required
        :param userInteraction_v31: CVSSv3.1 property User Interaction
        :param scope_v31: CVSSv3.1 property Scope
        :param confidentialityImpact_v31: CVSSv3.1 property Confidentiality Impact
        :param integrityImpact_v31: CVSSv3.1 property Integrity Impact
        :param availabilityImpact_v31: CVSSv3.1 property Availability Impact
        :param baseScore_v31: CVSSv3.1 property Base Score
        :param baseSeverity_v31: CVSSv3.1 property Base Severity
        :param exploitabilityScore_v31: CVSSv3.1 property Exploitability Score
        :param impactScore_v31: CVSSv3.1 property Impact Score
        :param vectorString_v40: CVSSv4.0 property Vector String
        :param attackVector_v40: CVSSv4.0 property Attack Vector
        :param attackComplexity_v40: CVSSv4.0 property Attack Complexity
        :param attackRequirements_v40: CVSSv4.0 property Attack Requirements
        :param privilegesRequired_v40: CVSSv4.0 property Privileges Required
        :param userInteraction_v40: CVSSv4.0 property User Interaction
        :param vulnerableSystemConfidentiality_v40: CVSSv4.0 property Vulnerable System Confidentiality Impact
        :param vulnerableSystemIntegrity_v40: CVSSv4.0 property Vulnerable System Integrity Impact
        :param vulnerableSystemAvailability_v40: CVSSv4.0 property Vulnerable System Availability Impact
        :param subsequentSystemConfidentiality_v40: CVSSv4.0 property Subsequent System Confidentiality Impact
        :param subsequentSystemIntegrity_v40: CVSSv4.0 property Subsequent System Integrity Impact
        :param subsequentSystemAvailability_v40: CVSSv4.0 property Subsequent System Availability Impact
        :param baseScore_v40: CVSSv4.0 property Base Score
        :param baseSeverity_v40: CVSSv4.0 property Base Severity
        :param cpe_type: CPE Type associated with the CVE
        :param ref_tags: References tags
        :param published: Publication date of the CVE
        :param lastModified: Last modified date of the CVE
        :param result_impacts: List of impacts determined by the categorizer
        :return:
        """
        self._run_query("CREATE (cve:CVE\
                                            {cve_id: $cve_id,\
                                            description: $description,\
                                            cwe: $cwe,\
                                            vector_string_v2: $vectorString_v2,\
                                            access_vector_v2: $accessVector_v2,\
                                            access_complexity_v2: $accessComplexity_v2,\
                                            authentication_v2: $authentication_v2,\
                                            confidentiality_impact_v2: $confidentialityImpact_v2,\
                                            integrity_impact_v2: $integrityImpact_v2,\
                                            availability_impact_v2: $availabilityImpact_v2,\
                                            base_score_v2: $baseScore_v2,\
                                            base_severity_v2: $baseSeverity_v2,\
                                            exploitability_score_v2: $exploitabilityScore_v2,\
                                            impact_score_v2: $impactScore_v2,\
                                            ac_insuf_info_v2: $acInsufInfo_v2,\
                                            obtain_all_privilege_v2: $obtainAllPrivilege_v2,\
                                            obtain_user_privilege_v2: $obtainUserPrivilege_v2,\
                                            obtain_other_privilege_v2: $obtainOtherPrivilege_v2,\
                                            user_interaction_required_v2: $userInteractionRequired_v2,\
                                            vector_string_v30: $vectorString_v30,\
                                            attack_vector_v30: $attackVector_v30,\
                                            attack_complexity_v30: $attackComplexity_v30,\
                                            privileges_required_v30: $privilegesRequired_v30,\
                                            user_interaction_v30: $userInteraction_v30,\
                                            scope_v30: $scope_v30,\
                                            confidentiality_impact_v30: $confidentialityImpact_v30,\
                                            integrity_impact_v30: $integrityImpact_v30,\
                                            availability_impact_v30: $availabilityImpact_v30,\
                                            base_score_v30: $baseScore_v30,\
                                            base_severity_v30: $baseSeverity_v30,\
                                            exploitability_score_v30: $exploitabilityScore_v30,\
                                            impact_score_v30: $impactScore_v30,\
                                            vector_string_v31: $vectorString_v31,\
                                            attack_vector_v31: $attackVector_v31,\
                                            attack_complexity_v31: $attackComplexity_v31,\
                                            privileges_required_v31: $privilegesRequired_v31,\
                                            user_interaction_v31: $userInteraction_v31,\
                                            scope_v31: $scope_v31,\
                                            confidentiality_impact_v31: $confidentialityImpact_v31,\
                                            integrity_impact_v31: $integrityImpact_v31,\
                                            availability_impact_v31: $availabilityImpact_v31,\
                                            base_score_v31: $baseScore_v31,\
                                            base_severity_v31: $baseSeverity_v31,\
                                            exploitability_score_v31: $exploitabilityScore_v31,\
                                            impact_score_v31: $impactScore_v31,\
                                            vector_string_v40: $vectorString_v40,\
                                            attack_vector_v40: $attackVector_v40,\
                                            attack_complexity_v40: $attackComplexity_v40,\
                                            attack_requirements_v40: $attackRequirements_v40,\
                                            privileges_required_v40: $privilegesRequired_v40,\
                                            user_interaction_v40: $userInteraction_v40,\
                                            vulnerable_system_confidentiality_v40: $vulnerableSystemConfidentiality_v40,\
                                            vulnerable_system_integrity_v40: $vulnerableSystemIntegrity_v40,\
                                            vulnerable_system_availability_v40: $vulnerableSystemAvailability_v40,\
                                            subsequent_system_confidentiality_v40: $subsequentSystemConfidentiality_v40,\
                                            subsequent_system_integrity_v40: $subsequentSystemIntegrity_v40,\
                                            subsequent_system_availability_v40: $subsequentSystemAvailability_v40,\
                                            base_score_v40: $baseScore_v40,\
                                            base_severity_v40: $baseSeverity_v40,\
                                            cpe_type: $cpe_type,\
                                            ref_tags: $ref_tags,\
                                            published: $published,\
                                            last_modified: $lastModified,\
                                            impact: $result_impacts})",
                        **{
                            'cve_id': cve_id,
                            'description': description,
                            'cwe': cwe,
                            'vectorString_v2': vectorString_v2,
                            'accessVector_v2': accessVector_v2,
                            'accessComplexity_v2': accessComplexity_v2,
                            'authentication_v2': authentication_v2,
                            'confidentialityImpact_v2': confidentialityImpact_v2,
                            'integrityImpact_v2': integrityImpact_v2,
                            'availabilityImpact_v2': availabilityImpact_v2,
                            'baseScore_v2': baseScore_v2,
                            'baseSeverity_v2': baseSeverity_v2,
                            'exploitabilityScore_v2': exploitabilityScore_v2,
                            'impactScore_v2': impactScore_v2,
                            'acInsufInfo_v2': acInsufInfo_v2,
                            'obtainAllPrivilege_v2': obtainAllPrivilege_v2,
                            'obtainUserPrivilege_v2': obtainUserPrivilege_v2,
                            'obtainOtherPrivilege_v2': obtainOtherPrivilege_v2,
                            'userInteractionRequired_v2': userInteractionRequired_v2,
                            'vectorString_v30': vectorString_v30,
                            'attackVector_v30': attackVector_v30,
                            'attackComplexity_v30': attackComplexity_v30,
                            'privilegesRequired_v30': privilegesRequired_v30,
                            'userInteraction_v30': userInteraction_v30,
                            'scope_v30': scope_v30,
                            'confidentialityImpact_v30': confidentialityImpact_v30,
                            'integrityImpact_v30': integrityImpact_v30,
                            'availabilityImpact_v30': availabilityImpact_v30,
                            'baseScore_v30': baseScore_v30,
                            'baseSeverity_v30': baseSeverity_v30,
                            'exploitabilityScore_v30': exploitabilityScore_v30,
                            'impactScore_v30': impactScore_v30,
                            'vectorString_v31': vectorString_v31,
                            'attackVector_v31': attackVector_v31,
                            'attackComplexity_v31': attackComplexity_v31,
                            'privilegesRequired_v31': privilegesRequired_v31,
                            'userInteraction_v31': userInteraction_v31,
                            'scope_v31': scope_v31,
                            'confidentialityImpact_v31': confidentialityImpact_v31,
                            'integrityImpact_v31': integrityImpact_v31,
                            'availabilityImpact_v31': availabilityImpact_v31,
                            'baseScore_v31': baseScore_v31,
                            'baseSeverity_v31': baseSeverity_v31,
                            'exploitabilityScore_v31': exploitabilityScore_v31,
                            'impactScore_v31': impactScore_v31,
                            'vectorString_v40': vectorString_v40,
                            'attackVector_v40': attackVector_v40,
                            'attackComplexity_v40': attackComplexity_v40,
                            'attackRequirements_v40': attackRequirements_v40,
                            'privilegesRequired_v40': privilegesRequired_v40,
                            'userInteraction_v40': userInteraction_v40,
                            'vulnerableSystemConfidentiality_v40': vulnerableSystemConfidentiality_v40,
                            'vulnerableSystemIntegrity_v40': vulnerableSystemIntegrity_v40,
                            'vulnerableSystemAvailability_v40': vulnerableSystemAvailability_v40,
                            'subsequentSystemConfidentiality_v40': subsequentSystemConfidentiality_v40,
                            'subsequentSystemIntegrity_v40': subsequentSystemIntegrity_v40,
                            'subsequentSystemAvailability_v40': subsequentSystemAvailability_v40,
                            'baseScore_v40': baseScore_v40,
                            'baseSeverity_v40': baseSeverity_v40,
                            'cpe_type': cpe_type,
                            'ref_tags': ref_tags,
                            'published': published,
                            'lastModified': lastModified,
                            'result_impacts': result_impacts})

    def create_relationship_between_cve_and_vulnerability(self, cve_id, vulnerability_description):
        """
        Creates relationship of type "REFERS_TO" between CVE and Vulnerability
        :param cve_id: id of CVE
        :param vulnerability_description: description of vulnerability
        :return:
        """
        self._run_query("MATCH (cve:CVE), (vul:Vulnerability) \
                         WHERE cve.cve_id = $cve_id AND vul.description = $description \
                         MERGE (vul)-[:REFERS_TO]->(cve)",
                        **{'cve_id': cve_id, 'description': vulnerability_description})

    def update_cve_from_nvd(self, 
                            cve_id, 
                            description, 
                            cwe,
                            vectorString_v2,
                            accessVector_v2,
                            accessComplexity_v2,
                            authentication_v2,
                            confidentialityImpact_v2,
                            integrityImpact_v2,
                            availabilityImpact_v2,
                            baseScore_v2,
                            baseSeverity_v2,
                            exploitabilityScore_v2,
                            impactScore_v2,
                            acInsufInfo_v2,
                            obtainAllPrivilege_v2,
                            obtainUserPrivilege_v2,
                            obtainOtherPrivilege_v2,
                            userInteractionRequired_v2,
                            vectorString_v30,
                            attackVector_v30,
                            attackComplexity_v30,
                            privilegesRequired_v30,
                            userInteraction_v30,
                            scope_v30,
                            confidentialityImpact_v30,
                            integrityImpact_v30,
                            availabilityImpact_v30,
                            baseScore_v30,
                            baseSeverity_v30,
                            exploitabilityScore_v30,
                            impactScore_v30,
                            vectorString_v31,
                            attackVector_v31,
                            attackComplexity_v31,
                            privilegesRequired_v31,
                            userInteraction_v31,
                            scope_v31,
                            confidentialityImpact_v31,
                            integrityImpact_v31,
                            availabilityImpact_v31,
                            baseScore_v31,
                            baseSeverity_v31,
                            exploitabilityScore_v31,
                            impactScore_v31,
                            vectorString_v40,
                            attackVector_v40,
                            attackComplexity_v40,
                            attackRequirements_v40,
                            privilegesRequired_v40,
                            userInteraction_v40,
                            vulnerableSystemConfidentiality_v40,
                            vulnerableSystemIntegrity_v40,
                            vulnerableSystemAvailability_v40,
                            subsequentSystemConfidentiality_v40,
                            subsequentSystemIntegrity_v40,
                            subsequentSystemAvailability_v40,
                            baseScore_v40,
                            baseSeverity_v40,
                            cpe_type,
                            ref_tags,
                            published,
                            lastModified,
                            result_impacts):
        """
        Updates an existing CVE node in the database with new details.

        :param cve_id: ID of the CVE
        :param description: Description of the CVE
        :param cwe: Common Weakness Enumeration (CWE) associated with the CVE
        :param vectorString_v2: CVSSv2 property Vector String
        :param accessVector_v2: CVSSv2 property Access Vector
        :param accessComplexity_v2: CVSSv2 property Access Complexity
        :param authentication_v2: CVSSv2 property Authentication
        :param confidentialityImpact_v2: CVSSv2 property Confidentiality Impact
        :param integrityImpact_v2: CVSSv2 property Integrity Impact
        :param availabilityImpact_v2: CVSSv2 property Availability Impact
        :param baseScore_v2: CVSSv2 property Base Score
        :param baseSeverity_v2: CVSSv2 property Base Severity
        :param exploitabilityScore_v2: CVSSv2 property Exploitability Score
        :param impactScore_v2: CVSSv2 property Impact Score
        :param acInsufInfo_v2: CVSSv2 property AC Insufficient Info
        :param obtainAllPrivilege_v2: CVSSv2 property Obtain All Privilege flag
        :param obtainUserPrivilege_v2: CVSSv2 property Obtain User Privilege flag
        :param obtainOtherPrivilege_v2: CVSSv2 property Obtain Other Privilege flag
        :param userInteractionRequired_v2: CVSSv2 property User Interaction Required flag
        :param vectorString_v30: CVSSv3.0 property Vector String
        :param attackVector_v30: CVSSv3.0 property Attack Vector
        :param attackComplexity_v30: CVSSv3.0 property Attack Complexity
        :param privilegesRequired_v30: CVSSv3.0 property Privileges Required
        :param userInteraction_v30: CVSSv3.0 property User Interaction
        :param scope_v30: CVSSv3.0 property Scope
        :param confidentialityImpact_v30: CVSSv3.0 property Confidentiality Impact
        :param integrityImpact_v30: CVSSv3.0 property Integrity Impact
        :param availabilityImpact_v30: CVSSv3.0 property Availability Impact
        :param baseScore_v30: CVSSv3.0 property Base Score
        :param baseSeverity_v30: CVSSv3.0 property Base Severity
        :param exploitabilityScore_v30: CVSSv3.0 property Exploitability Score
        :param impactScore_v30: CVSSv3.0 property Impact Score
        :param vectorString_v31: CVSSv3.1 property Vector String
        :param attackVector_v31: CVSSv3.1 property Attack Vector
        :param attackComplexity_v31: CVSSv3.1 property Attack Complexity
        :param privilegesRequired_v31: CVSSv3.1 property Privileges Required
        :param userInteraction_v31: CVSSv3.1 property User Interaction
        :param scope_v31: CVSSv3.1 property Scope
        :param confidentialityImpact_v31: CVSSv3.1 property Confidentiality Impact
        :param integrityImpact_v31: CVSSv3.1 property Integrity Impact
        :param availabilityImpact_v31: CVSSv3.1 property Availability Impact
        :param baseScore_v31: CVSSv3.1 property Base Score
        :param baseSeverity_v31: CVSSv3.1 property Base Severity
        :param exploitabilityScore_v31: CVSSv3.1 property Exploitability Score
        :param impactScore_v31: CVSSv3.1 property Impact Score
        :param vectorString_v40: CVSSv4.0 property Vector String
        :param attackVector_v40: CVSSv4.0 property Attack Vector
        :param attackComplexity_v40: CVSSv4.0 property Attack Complexity
        :param attackRequirements_v40: CVSSv4.0 property Attack Requirements
        :param privilegesRequired_v40: CVSSv4.0 property Privileges Required
        :param userInteraction_v40: CVSSv4.0 property User Interaction
        :param vulnerableSystemConfidentiality_v40: CVSSv4.0 property Vulnerable System Confidentiality Impact
        :param vulnerableSystemIntegrity_v40: CVSSv4.0 property Vulnerable System Integrity Impact
        :param vulnerableSystemAvailability_v40: CVSSv4.0 property Vulnerable System Availability Impact
        :param subsequentSystemConfidentiality_v40: CVSSv4.0 property Subsequent System Confidentiality Impact
        :param subsequentSystemIntegrity_v40: CVSSv4.0 property Subsequent System Integrity Impact
        :param subsequentSystemAvailability_v40: CVSSv4.0 property Subsequent System Availability Impact
        :param baseScore_v40: CVSSv4.0 property Base Score
        :param baseSeverity_v40: CVSSv4.0 property Base Severity
        :param cpe_type: CPE Type associated with the CVE
        :param ref_tags: References tags
        :param published: Publication date of the CVE
        :param lastModified: Last modified date of the CVE
        :param result_impacts: List of impacts determined by the categorizer
        :return:
        """
        self._run_query("MATCH (cve:CVE {cve_id: $cve_id})\
                                            SET cve.description = $description,\
                                                cve.cwe = $cwe,\
                                                cve.vector_string_v2 = $vectorString_v2,\
                                                cve.access_vector_v2 = $accessVector_v2,\
                                                cve.access_complexity_v2 = $accessComplexity_v2,\
                                                cve.authentication_v2 = $authentication_v2,\
                                                cve.confidentiality_impact_v2 = $confidentialityImpact_v2,\
                                                cve.integrity_impact_v2 = $integrityImpact_v2,\
                                                cve.availability_impact_v2 = $availabilityImpact_v2,\
                                                cve.base_score_v2 = $baseScore_v2,\
                                                cve.base_severity_v2 = $baseSeverity_v2,\
                                                cve.exploitability_score_v2 = $exploitabilityScore_v2,\
                                                cve.impact_score_v2 = $impactScore_v2,\
                                                cve.ac_insuf_info_v2 = $acInsufInfo_v2,\
                                                cve.obtain_all_privilege_v2 = $obtainAllPrivilege_v2,\
                                                cve.obtain_user_privilege_v2 = $obtainUserPrivilege_v2,\
                                                cve.obtain_other_privilege_v2 = $obtainOtherPrivilege_v2,\
                                                cve.user_interaction_required_v2 = $userInteractionRequired_v2,\
                                                cve.vector_string_v30 = $vectorString_v30,\
                                                cve.attack_vector_v30 = $attackVector_v30,\
                                                cve.attack_complexity_v30 = $attackComplexity_v30,\
                                                cve.privileges_required_v30 = $privilegesRequired_v30,\
                                                cve.user_interaction_v30 = $userInteraction_v30,\
                                                cve.scope_v30 = $scope_v30,\
                                                cve.confidentiality_impact_v30 = $confidentialityImpact_v30,\
                                                cve.integrity_impact_v30 = $integrityImpact_v30,\
                                                cve.availability_impact_v30 = $availabilityImpact_v30,\
                                                cve.base_score_v30 = $baseScore_v30,\
                                                cve.base_severity_v30 = $baseSeverity_v30,\
                                                cve.exploitability_score_v30 = $exploitabilityScore_v30,\
                                                cve.impact_score_v30 = $impactScore_v30,\
                                                cve.vector_string_v31 = $vectorString_v31,\
                                                cve.attack_vector_v31 = $attackVector_v31,\
                                                cve.attack_complexity_v31 = $attackComplexity_v31,\
                                                cve.privileges_required_v31 = $privilegesRequired_v31,\
                                                cve.user_interaction_v31 = $userInteraction_v31,\
                                                cve.scope_v31 = $scope_v31,\
                                                cve.confidentiality_impact_v31 = $confidentialityImpact_v31,\
                                                cve.integrity_impact_v31 = $integrityImpact_v31,\
                                                cve.availability_impact_v31 = $availabilityImpact_v31,\
                                                cve.base_score_v31 = $baseScore_v31,\
                                                cve.base_severity_v31 = $baseSeverity_v31,\
                                                cve.exploitability_score_v31 = $exploitabilityScore_v31,\
                                                cve.impact_score_v31 = $impactScore_v31,\
                                                cve.vector_string_v40 = $vectorString_v40,\
                                                cve.attack_vector_v40 = $attackVector_v40,\
                                                cve.attack_complexity_v40 = $attackComplexity_v40,\
                                                cve.attack_requirements_v40 = $attackRequirements_v40,\
                                                cve.privileges_required_v40 = $privilegesRequired_v40,\
                                                cve.user_interaction_v40 = $userInteraction_v40,\
                                                cve.vulnerable_system_confidentiality_v40 = $vulnerableSystemConfidentiality_v40,\
                                                cve.vulnerable_system_integrity_v40 = $vulnerableSystemIntegrity_v40,\
                                                cve.vulnerable_system_availability_v40 = $vulnerableSystemAvailability_v40,\
                                                cve.subsequent_system_confidentiality_v40 = $subsequentSystemConfidentiality_v40,\
                                                cve.subsequent_system_integrity_v40 = $subsequentSystemIntegrity_v40,\
                                                cve.subsequent_system_availability_v40 = $subsequentSystemAvailability_v40,\
                                                cve.base_score_v40 = $baseScore_v40,\
                                                cve.base_severity_v40 = $baseSeverity_v40,\
                                                cve.cpe_type = $cpe_type,\
                                                cve.ref_tags = $ref_tags,\
                                                cve.published = $published,\
                                                cve.last_modified = $lastModified,\
                                                cve.impact = $result_impacts",
                        **{
                            'cve_id': cve_id,
                            'description': description,
                            'cwe': cwe,
                            'vectorString_v2': vectorString_v2,
                            'accessVector_v2': accessVector_v2,
                            'accessComplexity_v2': accessComplexity_v2,
                            'authentication_v2': authentication_v2,
                            'confidentialityImpact_v2': confidentialityImpact_v2,
                            'integrityImpact_v2': integrityImpact_v2,
                            'availabilityImpact_v2': availabilityImpact_v2,
                            'baseScore_v2': baseScore_v2,
                            'baseSeverity_v2': baseSeverity_v2,
                            'exploitabilityScore_v2': exploitabilityScore_v2,
                            'impactScore_v2': impactScore_v2,
                            'acInsufInfo_v2': acInsufInfo_v2,
                            'obtainAllPrivilege_v2': obtainAllPrivilege_v2,
                            'obtainUserPrivilege_v2': obtainUserPrivilege_v2,
                            'obtainOtherPrivilege_v2': obtainOtherPrivilege_v2,
                            'userInteractionRequired_v2': userInteractionRequired_v2,
                            'vectorString_v30': vectorString_v30,
                            'attackVector_v30': attackVector_v30,
                            'attackComplexity_v30': attackComplexity_v30,
                            'privilegesRequired_v30': privilegesRequired_v30,
                            'userInteraction_v30': userInteraction_v30,
                            'scope_v30': scope_v30,
                            'confidentialityImpact_v30': confidentialityImpact_v30,
                            'integrityImpact_v30': integrityImpact_v30,
                            'availabilityImpact_v30': availabilityImpact_v30,
                            'baseScore_v30': baseScore_v30,
                            'baseSeverity_v30': baseSeverity_v30,
                            'exploitabilityScore_v30': exploitabilityScore_v30,
                            'impactScore_v30': impactScore_v30,
                            'vectorString_v31': vectorString_v31,
                            'attackVector_v31': attackVector_v31,
                            'attackComplexity_v31': attackComplexity_v31,
                            'privilegesRequired_v31': privilegesRequired_v31,
                            'userInteraction_v31': userInteraction_v31,
                            'scope_v31': scope_v31,
                            'confidentialityImpact_v31': confidentialityImpact_v31,
                            'integrityImpact_v31': integrityImpact_v31,
                            'availabilityImpact_v31': availabilityImpact_v31,
                            'baseScore_v31': baseScore_v31,
                            'baseSeverity_v31': baseSeverity_v31,
                            'exploitabilityScore_v31': exploitabilityScore_v31,
                            'impactScore_v31': impactScore_v31,
                            'vectorString_v40': vectorString_v40,
                            'attackVector_v40': attackVector_v40,
                            'attackComplexity_v40': attackComplexity_v40,
                            'attackRequirements_v40': attackRequirements_v40,
                            'privilegesRequired_v40': privilegesRequired_v40,
                            'userInteraction_v40': userInteraction_v40,
                            'vulnerableSystemConfidentiality_v40': vulnerableSystemConfidentiality_v40,
                            'vulnerableSystemIntegrity_v40': vulnerableSystemIntegrity_v40,
                            'vulnerableSystemAvailability_v40': vulnerableSystemAvailability_v40,
                            'subsequentSystemConfidentiality_v40': subsequentSystemConfidentiality_v40,
                            'subsequentSystemIntegrity_v40': subsequentSystemIntegrity_v40,
                            'subsequentSystemAvailability_v40': subsequentSystemAvailability_v40,
                            'baseScore_v40': baseScore_v40,
                            'baseSeverity_v40': baseSeverity_v40,
                            'cpe_type': cpe_type,
                            'ref_tags': ref_tags,
                            'published': published,
                            'lastModified': lastModified,
                            'result_impacts': result_impacts})

    def get_cve_patch(self, cve_id):
        """
        Return boolean value for CVE property 'patched'
        :param cve_id: ID of CVE
        :return:
        """
        with (self._driver.session()) as session:
            record = session.run("MATCH (node:CVE) \
                                  WHERE node.cve_id = $cve_id \
                                  RETURN node.patched",
                                 **{'cve_id': cve_id})
            data = record.single()
            if data is None:
                return None
            return data['node.patched']

    def get_cve(self, cve_id):
        """
        REturns CVE with specified id
        :param cve_id: id of CVE
        :return:
        """
        with (self._driver.session()) as session:
            return session.run("MATCH (cve:CVE) \
                                WHERE cve.cve_id = $cve_id \
                                RETURN {description: cve.description, cve_id: cve.cve_id, \
                                    published_date: cve.published_date} AS cve",
                               **{'cve_id': cve_id})

    def get_versions_of_product(self, vendor_and_product):
        """
        Get all software versions in the DB which have the same vendor and product name.
        :param vendor_and_product: vendor and product name of software
        :return:
        """
        product_string = vendor_and_product + ":"
        with (self._driver.session()) as session:
            return session.run("MATCH (s:SoftwareVersion) WHERE s.version STARTS WITH $product_string "
                               "RETURN {version: s.version} AS software",
                               **{'product_string': product_string}).data()
