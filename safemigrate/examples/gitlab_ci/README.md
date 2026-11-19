# SafeMigrate GitLab CI/CD Integration Example

This directory contains turnkey CI/CD configurations for integrating **SafeMigrate** into [GitLab CI/CD](https://docs.gitlab.com/ee/ci/) pipelines.

---

## Quickstart

Copy `.gitlab-ci.yml` into your repository root:
```bash
cp examples/gitlab_ci/.gitlab-ci.yml /path/to/your/repo/.gitlab-ci.yml
```

Whenever a developer opens a Merge Request modifying `.sql` migration files, GitLab CI will:
1. Spin up a lightweight Python container (`python:3.12-slim`).
2. Install SafeMigrate via pip directly from the public Git repository.
3. Statically audit all DDL statements in the specified directory.
4. Block the Merge Request if dangerous lock hazards (`AccessExclusiveLock`, table rewrites) are found.

---

## Configuration Variables

You can configure SafeMigrate in `.gitlab-ci.yml` using standard pipeline variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MIGRATIONS_DIR` | `migrations` | Path to directory containing migration `.sql` scripts. |
| `DIALECT` | `postgresql` | Database dialect: `postgresql` or `mysql`. |

---

## Multi-Service / Monorepo Example

If your repository contains multiple database services, define distinct lint jobs:

```yaml
stages:
  - lint

.safemigrate_template: &safemigrate_base
  stage: lint
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends git
    - pip install --upgrade pip
    - pip install "git+https://github.com/redintDev/drillops.git#subdirectory=safemigrate"

lint-auth-service:
  <<: *safemigrate_base
  script:
    - safemigrate check services/auth/migrations --dialect postgresql
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "services/auth/migrations/**/*"

lint-billing-service:
  <<: *safemigrate_base
  script:
    - safemigrate check services/billing/migrations --dialect mysql
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "services/billing/migrations/**/*"
```
