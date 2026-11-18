"""Rules registry for SafeMigrate."""

from safemigrate.models import Dialect
from safemigrate.rules.base import BaseRule
from safemigrate.rules.mysql import ALL_MYSQL_RULES
from safemigrate.rules.postgres import ALL_POSTGRES_RULES


def get_rules_for_dialect(dialect: Dialect = Dialect.POSTGRESQL):
    if dialect == Dialect.MYSQL:
        return ALL_MYSQL_RULES
    return ALL_POSTGRES_RULES
