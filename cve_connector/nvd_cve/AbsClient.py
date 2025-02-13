from neo4j import GraphDatabase, basic_auth


class AbstractClient:
    def __init__(self, bolt="bolt://localhost:7687", user="neo4j", password=None, driver=None, lifetime=200,
                 encrypted=False):
        self._user = user
        if driver is None:
            self._driver = GraphDatabase.driver(bolt, auth=basic_auth(user, password), max_connection_lifetime=lifetime,
                                                encrypted=encrypted)
        else:
            self._driver = driver

    def _run_query(self, query, **kwargs):
        with(self._driver.session()) as session:
            return session.run(query, **kwargs)

    def _get_driver(self):
        return self._driver

    def _close(self):
        self._driver.close()

    def init_db(self):
        """
        Create initial structure
        """
        constraints = ['CREATE CONSTRAINT ON (n:Contact) ASSERT n.name IS UNIQUE',
                       'CREATE CONSTRAINT ON (n:DetectionSystem) ASSERT n.name IS UNIQUE',
                       'CREATE CONSTRAINT ON (p:IP) ASSERT p.address IS UNIQUE',
                       'CREATE CONSTRAINT ON (o:OrganizationUnit) ASSERT o.name IS UNIQUE',
                       'CREATE CONSTRAINT ON (n:Subnet) ASSERT n.range IS UNIQUE',
                       'CREATE CONSTRAINT ON (c:CVE) ASSERT c.CVE_id IS UNIQUE',
                       'CREATE CONSTRAINT ON (v:Vulnerability) ASSERT v.description IS UNIQUE',
                       'CREATE CONSTRAINT ON (n:Mission) ASSERT n.name IS UNIQUE',
                       'CREATE CONSTRAINT ON (n:Component) ASSERT n.name IS UNIQUE',
                       'CREATE CONSTRAINT ON (n:Host) ASSERT n.hostname IS UNIQUE']

        for constraint in constraints:
            self._run_query(constraint)
