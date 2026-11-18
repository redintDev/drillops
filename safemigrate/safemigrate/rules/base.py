"""Base rule class for SafeMigrate."""

from abc import ABC, abstractmethod
from typing import List, Optional

from safemigrate.models import Dialect, Violation
from safemigrate.parser import ParsedStatement


class BaseRule(ABC):
    """Abstract base class for all database migration safety rules."""

    rule_id: str
    name: str
    description: str
    dialect: Dialect = Dialect.POSTGRESQL

    @abstractmethod
    def evaluate(
        self,
        statement: ParsedStatement,
        all_statements: List[ParsedStatement]
    ) -> Optional[Violation]:
        """Evaluates a statement and returns a Violation if an unsafe pattern is found."""
        pass
