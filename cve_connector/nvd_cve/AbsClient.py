from __future__ import annotations

from typing import Any, LiteralString

from neo4j import Driver, GraphDatabase, Query, Result, basic_auth


class AbstractClient:
    """
    Abstract Client for interacting with the Neo4j database.
    """

    def __init__(
        self,
        bolt: str,
        user: str,
        password: str | None = None,
        driver: Driver | None = None,
        lifetime: int = 200,
        encrypted: bool = False,
    ) -> None:
        self._user: str = user
        if driver is None:
            if password is None:
                raise ValueError("password must be provided when driver is None")
            self._driver: Driver = GraphDatabase.driver(
                bolt,
                auth=basic_auth(user, password),
                max_connection_lifetime=lifetime,
                encrypted=encrypted,
            )
        else:
            self._driver = driver

    def _run_query(self, query: LiteralString | Query, **kwargs: Any) -> Result:
        with self._driver.session() as session:
            return session.run(query, **kwargs)

    def _get_driver(self) -> Driver:
        return self._driver

    def _close(self) -> None:
        self._driver.close()
