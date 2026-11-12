# DrillOps Commercial Pricing & Tier Architecture

DrillOps uses a developer-first open-core model designed to turn disaster recovery testing from an overlooked chore into an automated, auditor-certified compliance workflow.

---

## 1. Feature Matrix & Tier Comparison

| Feature / Capability | Community Edition | Self-Hosted Pro | Enterprise Tier |
| :--- | :---: | :---: | :---: |
| **Pricing** | **$0 / Free Forever** | **$79 / year** | **$199 / year** |
| **Target Audience** | Solo Devs, OSS projects | Startups, SOC2 candidates | Scale-ups, Multi-cluster teams |
| **Engine Support (Postgres, SQLite)** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Interactive Demo (`drillops demo`)** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Custom SQL Assertions** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Schema Drift Detection** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Turnkey CI/CD GitHub Action** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Monitored Targets** | 1 Target | Up to 10 Targets | **Unlimited** |
| **Scheduled Watcher Daemon (`drillops watch`)** | Single run | ✅ Continuous Daemon | ✅ Continuous Daemon |
| **Embedded Web Dashboard (`drillops serve`)** | - | ✅ Full Access | ✅ Full Access |
| **SOC2 / ISO 27001 ZIP Dossier Packager** | - | ✅ Automated | ✅ White-Label / Custom Branding |
| **Multi-Channel Alerting (Slack, Discord, PagerDuty)** | - | ✅ Full Support | ✅ Full Support |
| **Declarative Multi-Target Orchestrator** | - | ✅ Full Support | ✅ Full Support |
| **Air-Gapped / Offline Verification** | ✅ Yes | ✅ Cryptographic Token | ✅ Cryptographic Token |
| **Support SLA** | Community / GitHub | Standard Email | Priority Engineering |

---

## 2. Licensing Mechanism (Zero DRM Infrastructure)

DrillOps Pro and Enterprise tiers utilize **offline cryptographic signature verification** via HMAC-SHA256 signed tokens (`DRILLOPS-V1.<payload>.<signature>`).

### Key Benefits for Customers:
- **No DRM Phone-Home**: Works in completely air-gapped VPCs, GovCloud, or isolated offline environments.
- **Instant Activation**: Simply set the environment variable in your Docker container, Kubernetes Pod, or CI pipeline:
  ```bash
  export DRILLOPS_LICENSE_KEY="DRILLOPS-V1.eyJpZCI6IkxJQy1QUk8...<signature>"
  ```
- **Inspect Anytime**:
  ```bash
  drillops license info
  ```

---

## 3. Self-Service Checkout Integration

Licenses can be purchased via self-service Stripe or LemonSqueezy payment links. Upon successful checkout, the fulfillment webhook automatically generates the cryptographic token and emails it to the customer along with immediate setup instructions.
