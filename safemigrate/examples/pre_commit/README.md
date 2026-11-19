# SafeMigrate Git Pre-Commit Hooks Example

This directory contains turnkey configuration examples for integrating **SafeMigrate** as a git pre-commit hook via [pre-commit](https://pre-commit.com/).

---

## Quickstart

1. Copy `.pre-commit-config.yaml` to the root of your git repository:
   ```bash
   cp examples/pre_commit/.pre-commit-config.yaml /path/to/your/repo/.pre-commit-config.yaml
   ```

2. Install pre-commit (if not already installed):
   ```bash
   pip install pre-commit
   ```

3. Enable the git hook scripts:
   ```bash
   pre-commit install
   ```

Now, whenever you stage `.sql` migration files and run `git commit`, SafeMigrate will automatically validate your migrations before they can be committed.

---

## Available Hooks

The root manifest `.pre-commit-hooks.yaml` on `https://github.com/redintDev/drillops` provides three specialized hooks:

| Hook ID | CLI Entrypoint | Behavior | Recommended Use Case |
| :--- | :--- | :--- | :--- |
| `safemigrate-fix` | `safemigrate fix -i` | **Automatic In-Place Rewrite**: Automatically injects `CONCURRENTLY`, `NOT VALID`, and `lock_timeout` into staged migration files. | Developer workstations desiring automatic safe rewrites on commit. |
| `safemigrate-check` | `safemigrate fix --check` | **Dry-Run Validation**: Blocks the commit and exits with code 1 if any staged migration requires safe remediation. | Teams requiring explicit manual review before rewrites are applied. |
| `safemigrate` | `safemigrate lint` | **Static Lock Linter**: Inspects lock modes and reports violation tables with rule IDs and severity levels. | General-purpose linting and CI commit hooks. |

---

## Configuration Example

```yaml
repos:
  - repo: https://github.com/redintDev/drillops
    rev: main
    hooks:
      # Automatically rewrite unsafe DDL in staged SQL files
      - id: safemigrate-fix

      # Or fail commit if unsafe DDL is present
      # - id: safemigrate-check

      # Or lint only with strict severity enforcement
      # - id: safemigrate
      #   args: ["--strict", "--dialect", "postgresql"]
```

---

## Manual Execution

To audit all migration files across your repository at any time:
```bash
pre-commit run safemigrate --all-files
```
