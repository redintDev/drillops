"""Terminal ANSI formatter for SafeMigrate."""

import sys
from safemigrate.models import LintResult, Severity


class TerminalFormatter:
    """Formats lint results for human CLI display."""

    COLOR_RESET = "\033[0m"
    COLOR_RED = "\033[31m"
    COLOR_YELLOW = "\033[33m"
    COLOR_GREEN = "\033[32m"
    COLOR_CYAN = "\033[36m"
    COLOR_BOLD = "\033[1m"
    COLOR_GRAY = "\033[90m"

    @classmethod
    def format(cls, result: LintResult, use_color: bool = True) -> str:
        lines = []
        c_reset = cls.COLOR_RESET if use_color else ""
        c_bold = cls.COLOR_BOLD if use_color else ""
        c_red = cls.COLOR_RED if use_color else ""
        c_yellow = cls.COLOR_YELLOW if use_color else ""
        c_green = cls.COLOR_GREEN if use_color else ""
        c_cyan = cls.COLOR_CYAN if use_color else ""
        c_gray = cls.COLOR_GRAY if use_color else ""

        lines.append(f"{c_bold}SafeMigrate Linter: {result.file_path}{c_reset}")
        lines.append("=" * 60)

        if not result.violations:
            lines.append(f"{c_green}✔ No database lock hazards detected. Migration appears safe.{c_reset}")
            return "\n".join(lines)

        for v in result.violations:
            sev_color = c_red if v.severity in (Severity.CRITICAL, Severity.HIGH) else (c_yellow if v.severity == Severity.MEDIUM else c_cyan)
            lines.append(f"\n[{sev_color}{v.severity.value}{c_reset}] {c_bold}{v.rule_id} ({v.rule_name}){c_reset} at line {v.line_number}:")
            lines.append(f"  {v.message}")
            lines.append(f"  {c_gray}SQL: {v.statement.splitlines()[0]}{c_reset}")

            if v.remediation:
                lines.append(f"  {c_green}Remediation Plan: {v.remediation.title}{c_reset}")
                for step in v.remediation.steps:
                    lines.append(f"    {step}")

        lines.append("\n" + "-" * 60)
        status_text = f"{c_red}FAILED{c_reset}" if not result.passed else f"{c_green}PASSED (with warnings){c_reset}"
        lines.append(f"Summary: {status_text} | Critical: {result.critical_count} | High: {result.high_count} | Medium: {result.medium_count} | Low: {result.low_count}")
        return "\n".join(lines)
