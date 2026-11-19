"""CLI entry point for SafeMigrate."""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import List

from safemigrate import __version__
from safemigrate.fixer import MigrationFixer
from safemigrate.formatters.github_pr import GitHubPRFormatter
from safemigrate.formatters.terminal import TerminalFormatter
from safemigrate.linter import SafeMigrateLinter
from safemigrate.models import Dialect, LintResult, Severity


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safemigrate",
        description="SafeMigrate: Zero-Downtime Database Migration Linter & Safety Auditor",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: lint <files...>
    lint_parser = subparsers.add_parser("lint", help="Lint one or more SQL migration files")
    lint_parser.add_argument("files", nargs="+", help="Path(s) to SQL migration file(s)")
    lint_parser.add_argument("--dialect", default="postgresql", choices=["postgresql", "mysql"], help="SQL dialect")
    lint_parser.add_argument("--format", default="terminal", choices=["terminal", "github", "json"], help="Output format")
    lint_parser.add_argument("--strict", action="store_true", help="Fail on MEDIUM severity warnings as well as CRITICAL/HIGH")

    # Command: check <directory>
    check_parser = subparsers.add_parser("check", help="Scan a directory for migration files")
    check_parser.add_argument("directory", help="Directory containing migration files")
    check_parser.add_argument("--dialect", default="postgresql", choices=["postgresql", "mysql"], help="SQL dialect")
    check_parser.add_argument("--format", default="terminal", choices=["terminal", "github", "json"], help="Output format")
    check_parser.add_argument("--strict", action="store_true", help="Fail on MEDIUM severity warnings as well as CRITICAL/HIGH")

    # Command: fix <paths...>
    fix_parser = subparsers.add_parser("fix", help="Automatically rewrite dangerous migrations into safe zero-downtime DDL")
    fix_parser.add_argument("paths", nargs="+", help="Path(s) to SQL migration file(s) or directories to rewrite")
    fix_parser.add_argument("-o", "--out", help="Write safe SQL to specified output file instead of stdout (single file only)")
    fix_parser.add_argument("-i", "--in-place", action="store_true", help="Modify the input file(s) in place")
    fix_parser.add_argument("--diff", action="store_true", help="Show unified diff of changes")
    fix_parser.add_argument("--check", action="store_true", help="Check whether migrations require fixes without modifying them (exit 1 if fixes needed)")
    fix_parser.add_argument("--dialect", default="postgresql", choices=["postgresql", "mysql"], help="SQL dialect")

    # Command: rules
    rules_parser = subparsers.add_parser("rules", help="List all migration safety rules and hazards")
    rules_parser.add_argument("--dialect", default=None, choices=["postgresql", "mysql"], help="Filter rules by dialect (default: all)")
    rules_parser.add_argument("--format", default="terminal", choices=["terminal", "json"], help="Output format")

    return parser


def handle_results(results: List[LintResult], output_format: str, strict: bool) -> int:
    exit_code = 0

    if output_format == "json":
        payload = [
            {
                "file": r.file_path,
                "passed": r.passed if not strict else (r.passed and r.medium_count == 0),
                "critical": r.critical_count,
                "high": r.high_count,
                "medium": r.medium_count,
                "low": r.low_count,
                "violations": [v.to_dict() for v in r.violations],
            }
            for r in results
        ]
        print(json.dumps(payload, indent=2))
    elif output_format == "github":
        for r in results:
            ann = GitHubPRFormatter.format_annotations(r)
            if ann:
                print(ann)
            print(GitHubPRFormatter.format_summary_markdown(r))
    else:  # terminal
        for r in results:
            print(TerminalFormatter.format(r))
            print()

    for r in results:
        if not r.passed:
            exit_code = 1
        elif strict and r.medium_count > 0:
            exit_code = 1

    return exit_code


def main(args: List[str] = None) -> int:
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    if parsed_args.command == "rules":
        from safemigrate.rules.mysql import ALL_MYSQL_RULES
        from safemigrate.rules.postgres import ALL_POSTGRES_RULES

        if parsed_args.dialect == "postgresql":
            selected_rules = ALL_POSTGRES_RULES
        elif parsed_args.dialect == "mysql":
            selected_rules = ALL_MYSQL_RULES
        else:
            selected_rules = ALL_POSTGRES_RULES + ALL_MYSQL_RULES

        if parsed_args.format == "json":
            payload = [
                {
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "dialect": r.dialect.value,
                    "description": r.description,
                }
                for r in selected_rules
            ]
            print(json.dumps(payload, indent=2))
            return 0
        else:
            print("SafeMigrate Safety Rule Catalog")
            print("=" * 80)
            print(f"{'Rule ID':<12} {'Dialect':<12} {'Rule Name':<35} {'Description'}")
            print("-" * 80)
            for r in selected_rules:
                print(f"{r.rule_id:<12} {r.dialect.value:<12} {r.name:<35} {r.description}")
            print("=" * 80)
            print(f"Total Rules: {len(selected_rules)}")
            return 0

    dialect = Dialect(parsed_args.dialect)
    linter = SafeMigrateLinter(dialect=dialect)

    try:
        if parsed_args.command == "lint":
            results = [linter.lint_file(f) for f in parsed_args.files]
            return handle_results(results, parsed_args.format, parsed_args.strict)
        elif parsed_args.command == "check":
            results = linter.lint_directory(parsed_args.directory)
            if not results:
                print(f"No SQL migration files found in '{parsed_args.directory}'.")
                return 0
            return handle_results(results, parsed_args.format, parsed_args.strict)
        elif parsed_args.command == "fix":
            fixer = MigrationFixer(dialect=dialect)

            # Collect files from paths (which can be files or directories)
            target_files = []
            for p_str in parsed_args.paths:
                p = Path(p_str)
                if p.is_dir():
                    target_files.extend(sorted(str(f) for f in p.rglob("*.sql")))
                elif p.is_file():
                    target_files.append(str(p))
                else:
                    print(f"Error: Path '{p_str}' does not exist.", file=sys.stderr)
                    return 2

            if not target_files:
                print("No SQL migration files found to fix.", file=sys.stderr)
                return 0

            if parsed_args.out and len(target_files) > 1:
                print("Error: -o/--out cannot be used with multiple files.", file=sys.stderr)
                return 2

            total_fixes = 0
            files_modified = 0
            exit_code = 0

            for f_path in target_files:
                res, diff = fixer.fix_file(f_path)
                
                if res.fixes_applied > 0:
                    files_modified += 1
                    total_fixes += res.fixes_applied

                if not res.passed:
                    exit_code = 1

                if parsed_args.check:
                    if res.fixes_applied > 0:
                        print(f"✖ SafeMigrate check: '{f_path}' would be reformatted ({res.fixes_applied} hazard(s) remediated)")
                        if parsed_args.diff:
                            print(diff)
                elif parsed_args.diff and not parsed_args.in_place and not parsed_args.out:
                    if diff:
                        print(diff)
                elif parsed_args.in_place:
                    if res.fixes_applied > 0:
                        with open(f_path, "w", encoding="utf-8") as f:
                            f.write(res.fixed_sql)
                        print(f"✔ SafeMigrate: Fixed {res.fixes_applied} hazard(s) in '{f_path}' in-place.")
                        if parsed_args.diff:
                            print(diff)
                elif parsed_args.out:
                    with open(parsed_args.out, "w", encoding="utf-8") as f:
                        f.write(res.fixed_sql)
                    print(f"✔ SafeMigrate: Wrote safe migration with {res.fixes_applied} fix(es) to '{parsed_args.out}'.")
                    if parsed_args.diff:
                        print(diff)
                else:
                    # Single file default to stdout
                    if len(target_files) == 1:
                        sys.stdout.write(res.fixed_sql)
                    else:
                        if res.fixes_applied > 0:
                            print(f"• '{f_path}': {res.fixes_applied} hazard(s) detected (use -i to fix in-place or --diff)")

            if parsed_args.check:
                if files_modified > 0:
                    print(f"\nSafeMigrate check failed: {files_modified} file(s) would be modified ({total_fixes} hazard(s) total). Run 'safemigrate fix -i' to apply fixes.")
                    return 1
                else:
                    print(f"✔ SafeMigrate check passed: all {len(target_files)} file(s) clean and zero-downtime safe.")
                    return 0

            if len(target_files) > 1 and (parsed_args.in_place or not parsed_args.diff):
                print(f"Summary: {files_modified} of {len(target_files)} file(s) modified, {total_fixes} total hazard(s) remediated.")

            return exit_code
    except Exception as e:
        print(f"SafeMigrate error: {e}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
