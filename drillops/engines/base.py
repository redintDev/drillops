"""Abstract base engine for database restoration and query execution."""

from abc import ABC, abstractmethod
from typing import Any, List


class BaseRestoreEngine(ABC):
    """Interface that every database engine must implement for DrillOps."""

    @abstractmethod
    def setup_ephemeral_db(self) -> None:
        """Create or initialize the isolated test database environment."""
        pass

    @abstractmethod
    def restore_dump(self, dump_path: str) -> float:
        """
        Execute the restore of the dump payload into the ephemeral database.
        Returns the duration of the restore in seconds.
        """
        pass

    @abstractmethod
    def execute_query(self, query: str) -> Any:
        """Execute a query against the restored database and return results."""
        pass

    @abstractmethod
    def list_tables(self) -> List[str]:
        """List all user tables present in the restored database."""
        pass

    @abstractmethod
    def teardown(self) -> None:
        """Drop the ephemeral database and cleanly release all resources."""
        pass
