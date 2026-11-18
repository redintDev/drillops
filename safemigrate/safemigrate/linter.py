"""SafeMigrate core linter engine."""

import os
from pathlib import Path
from typing import List

from safemigrate.models import Dialect, LintResult
from safemigrate.parser import MigrationParser
from safemigrate.rules import get_rules_for_dialect


class SafeMigrateLinter:
    """Core engine to evaluate migration SQL files against safety rules."""

    def __init__(self, dialect: Dialect = Dialect.POSTGRESQL):
        self.dialect = dialect
        self.rules = get_rules_for_dialect(dialect)

    def lint_string(self, content: str, file_path: str = "<stdin>") -> LintResult:
        statements = MigrationParser.parse_sql(content)
        result = LintResult(file_path=file_path)

        for stmt in statements:
            for rule in self.rules:
                violation = rule.evaluate(stmt, statements)
                if violation:
                    result.violations.append(violation)

        return result

    def lint_file(self, file_path: str) -> LintResult:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Migration file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        return self.lint_string(content, file_path=file_path)

    def lint_directory(self, dir_path: str, extensions: tuple = (".sql",)) -> List[LintResult]:
        results: List[LintResult] = []
        path = Path(dir_path)

        if not path.is_dir():
            raise NotADirectoryError(f"Directory not found: {dir_path}")

        # Scan for matching migration files recursively
        for root, _, files in os.walk(path):
            for file in sorted(files):
                if any(file.endswith(ext) for ext in extensions):
                    full_path = os.path.join(root, file)
                    results.append(self.lint_file(full_path))

        return results
