# QuietPhysics Security Invariant Gate (GitHub Action)

> **Deterministic, pre-merge cloud security verification for Terraform, AWS, and Kubernetes PRs.**

QuietPhysics evaluates proposed Infrastructure-as-Code changes
(`G1 = G0 ⊕ Δ_IaC`) **before merge** to prove whether a PR creates a
reachable attack path from the internet to sensitive databases,
encryption keys, or cloud credentials.

Not yet published to the GitHub Marketplace or tagged with a release
version — reference it by branch (`@main`) until that exists, not `@v1`.

---

## 🚀 Quickstart: add to your repository

Create `.github/workflows/security-gate.yml`:

```yaml
name: QuietPhysics Security Gate

on:
  pull_request:
    branches: [ main, master, staging ]
    paths:
      - '**.tf'
      - '**.tfvars'
      - '**.yaml'
      - '**.yml'

permissions:
  contents: read
  pull-requests: write # Required for the PR comment bot

jobs:
  verify-security:
    name: Verify Security Invariants
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run QuietPhysics Invariant Gate
        uses: Evgsoft/quietPhysics-github-marketplace@main
        with:
          api-key: ${{ secrets.QP_API_KEY }}
          basic-auth-username: ${{ secrets.QP_BASIC_AUTH_USERNAME }}
          basic-auth-password: ${{ secrets.QP_BASIC_AUTH_PASSWORD }}
          scenario: 'all'
          fail-on-regression: 'true'
          post-pr-comment: 'true'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

`api-key` is your own per-tenant key. `basic-auth-username`/
`basic-auth-password` are a separate, shared credential gating the whole
QuietPhysics Cloud API on top of that — issued alongside your API key,
not the same thing. Both are required; the action fails fast with a clear
message if either is missing.

---

## ⚙️ Inputs reference

| Input | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| `api-key` | Your QuietPhysics Cloud API key (per-tenant, sent as `X-API-Key`) | **Yes** | `${{ secrets.QP_API_KEY }}` |
| `basic-auth-username` | Shared QuietPhysics Cloud access username (see above) | **Yes** | `${{ secrets.QP_BASIC_AUTH_USERNAME }}` |
| `basic-auth-password` | Shared QuietPhysics Cloud access password (see above) | **Yes** | `${{ secrets.QP_BASIC_AUTH_PASSWORD }}` |
| `api-url` | QuietPhysics Cloud endpoint | No | `https://api.quietphysics.com/v1/evaluate` |
| `scenario` | Invariant pack to evaluate (`all` or `1`-`8`) | No | `all` |
| `mode` | Evaluation mode: `pr-regression` or `baseline` | No | `pr-regression` |
| `fail-on-regression` | Exit non-zero on a detected regression | No | `true` |
| `post-pr-comment` | Post the rich attack-path breakdown to the PR | No | `true` |
| `github-token` | GitHub token for posting PR comments | No | `${{ github.token }}` |

---

## 💬 Sample PR comment

When a pull request introduces an attack path, QuietPhysics blocks the
deployment and posts a breakdown like this:

```text
## 🛡️ QuietPhysics Security Invariant Gate
Status: ❌ DEPLOYMENT BLOCKED | Passed: 0/8

🚨 DISCOVERED PROHIBITED ATTACK PATH (G1):
  [1] Internet (0.0.0.0/0)
     └─▶ [2] qp-demo-alb-sg (Port 443 HTTPS)
          └─▶ [3] payments-api (Namespace: payments)
               └─▶ [4] qp-demo-payments-workload-role
                    └─▶ [5] sts:AssumeRole 🚨 [PROPOSED in iam_regression.tf:L5]
                         └─▶ [6] qp-demo-production-admin-role
                              └─▶ [7] ProductionDB (RDS Postgres / Secrets Manager)

🛠️ COUNTERFACTUAL REMEDIATION (G_fix):
  Remove 'payments_assume_production_admin' IAM policy attachment.
```

Only appears for the full `scenario: 'all'` run today — single-scenario
runs (`scenario: '1'`-`'8'`) get a plain terminal-style result instead
(see `plans/03-github-action-client.md` #5).
