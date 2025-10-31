from neo4j import GraphDatabase, basic_auth


class AbstractClient:
    """
    Abstract Client for interacting with the Neo4j database.
    """
    def __init__(
        self, bolt="bolt://localhost:7687", user="neo4j", password=None, driver=None, lifetime=200, encrypted=False
    ) -> None:
        self._user = user
        if driver is None:
            self._driver = GraphDatabase.driver(
                bolt, auth=basic_auth(user, password), max_connection_lifetime=lifetime, encrypted=encrypted
            )
        else:
            self._driver = driver

    def _run_query(self, query, **kwargs):
        with self._driver.session() as session:
            return session.run(query, **kwargs)

    def _get_driver(self):
        return self._driver

    def _close(self) -> None:
        self._driver.close()
