"""GitHub Actions annotations and Step Summary markdown formatter."""

from safemigrate.models import LintResult, Severity


class GitHubPRFormatter:
    """Formats lint results for GitHub Actions workflow annotations and summary markdown."""

    @staticmethod
    def format_annotations(result: LintResult) -> str:
        """Formats GitHub Actions workflow command annotations (::error or ::warning)."""
        lines = []
        for v in result.violations:
            level = "error" if v.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
            # Format: ::warning file={name},line={line},title={title}::{message}
            lines.append(
                f"::{level} file={result.file_path},line={v.line_number},title={v.rule_id}: {v.rule_name}::{v.message}"
            )
        return "\n".join(lines)

    @staticmethod
    def format_summary_markdown(result: LintResult) -> str:
        """Generates rich markdown suitable for $GITHUB_STEP_SUMMARY."""
        status_badge = "❌ **MIGRATION BLOCKED (Lock Hazards Detected)**" if not result.passed else "✅ **MIGRATION SAFE**"
        
        md = [
            f"## SafeMigrate DDL Lock Audit: `{result.file_path}`",
            "",
            status_badge,
            "",
            "| Rule | Severity | Line | Hazard Description |",
            "| :--- | :---: | :---: | :--- |"
        ]

        for v in result.violations:
            md.append(f"| `{v.rule_id}` | **{v.severity.value}** | L{v.line_number} | {v.message} |")

        if any(v.remediation for v in result.violations):
            md.append("\n### 🛠️ Zero-Downtime Safe Remediation Recipes\n")
            for v in result.violations:
                if v.remediation:
                    md.append(f"#### `{v.rule_id}`: {v.remediation.title}")
                    md.append(f"*{v.remediation.description}*\n")
                    md.append("```sql")
                    for step in v.remediation.steps:
                        md.append(step)
                    md.append("```\n")

        return "\n".join(md)
