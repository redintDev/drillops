# SafeMigrate Bitbucket Pipelines Integration Example

This directory contains turnkey CI/CD configurations for integrating **SafeMigrate** into [Bitbucket Pipelines](https://support.atlassian.com/bitbucket-cloud/docs/get-started-with-bitbucket-pipelines/).

---

## Quickstart

Copy `bitbucket-pipelines.yml` into your repository root:
```bash
cp examples/bitbucket_pipelines/bitbucket-pipelines.yml /path/to/your/repo/bitbucket-pipelines.yml
```

Whenever a developer opens a Pull Request on Bitbucket, the pipeline will:
1. Spin up a fast, lightweight Python container (`python:3.12-slim`).
2. Leverage Bitbucket pip caching for instant installs.
3. Install SafeMigrate directly from the public Git repository.
4. Statically audit all DDL statements in the migrations directory.
5. Block the Pull Request build if dangerous lock hazards (`AccessExclusiveLock`, table rewrites) are detected.

---

## Pipeline Configuration & Variables

You can configure SafeMigrate in `bitbucket-pipelines.yml` or via **Repository Settings > Repository variables**:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MIGRATIONS_DIR` | `migrations` | Directory containing SQL migration scripts. |
| `DIALECT` | `postgresql` | Database dialect: `postgresql` or `mysql`. |

---

## Monorepo / Multi-Dialect Example

If your repository contains multiple database services:

```yaml
image: python:3.12-slim

definitions:
  caches:
    pip: ~/.cache/pip
  steps:
    - step: &lint-postgres
        name: Audit PostgreSQL Migrations
        caches: [pip]
        script:
          - apt-get update && apt-get install -y --no-install-recommends git
          - pip install --upgrade pip
          - pip install "git+https://github.com/redintDev/drillops.git#subdirectory=safemigrate"
          - safemigrate check services/auth/migrations --dialect postgresql

    - step: &lint-mysql
        name: Audit MySQL Migrations
        caches: [pip]
        script:
          - apt-get update && apt-get install -y --no-install-recommends git
          - pip install --upgrade pip
          - pip install "git+https://github.com/redintDev/drillops.git#subdirectory=safemigrate"
          - safemigrate check services/billing/migrations --dialect mysql

pipelines:
  pull-requests:
    '**':
      - step: *lint-postgres
      - step: *lint-mysql
```
