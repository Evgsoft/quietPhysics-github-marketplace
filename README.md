# QuietPhysics Security Invariant Gate (GitHub Action)

> **Deterministic, pre-merge cloud security verification for Terraform, AWS, and Kubernetes PRs.**

QuietPhysics checks the Terraform plan and Kubernetes manifests of a pull
request **before merge** against 10 built-in rules (IAM, network, S3, data
stores, secrets, Kubernetes) and fails the check when a change breaks one.
It reads the plan you send; it does not read your live cloud. Without a
plan the Action answers from built-in demo scenarios, and the sample comment
at the end of this page is the output format of those scenarios.

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
          scenario: 'all'
          fail-on-regression: 'true'
          post-pr-comment: 'true'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

`api-key` is your own per-tenant key — that's all you need. (If
QuietPhysics separately gave you a shared `basic-auth-username`/
`basic-auth-password` pair for closed-beta access, add those too; most
customers won't have one and don't need it.)

---

## 📄 Judge your own Terraform plan and Kubernetes manifests

By default the gate answers from built-in demo scenarios. Give it a plan and/or manifests and it judges **your** changes instead:

```yaml
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_wrapper: false      # so `terraform show -json` prints clean JSON
      - name: Plan
        working-directory: infra
        run: |
          terraform init -input=false
          terraform plan -input=false -out=tfplan
          terraform show -json tfplan > plan.json
      - uses: Evgsoft/quietPhysics-github-marketplace@main
        with:
          api-key: ${{ secrets.QP_API_KEY }}
          plan-file: infra/plan.json
          terraform-dir: infra                     # lets findings point at file:line
          manifest-files: |                        # optional
            k8s/**/*.yaml
          aws-account-ids: '123456789012'          # optional: your own account ids
          on-inconclusive: warn                    # or: fail
```

Plan analysis has to be switched on for your tenant by QuietPhysics. If it is not, the step **fails** with "no analysis ran"
rather than approving something that was not looked at.

### Verdicts

| Verdict | Meaning | Job result |
| :--- | :--- | :--- |
| `APPROVED` | Every supported resource in the input was judged and none violates a rule | passes |
| `BLOCKED` | A rule is violated (the comment names the resource and, if found, its `file:line`) | fails (unless `fail-on-regression: 'false'`) |
| `INCONCLUSIVE` | A value that decides the answer is not known until apply (for example a policy ARN computed by another resource) | `on-inconclusive: warn` (default) passes with a warning annotation; `fail` fails |
| `SKIPPED` | Nothing QuietPhysics checks was found: a plan with no resource types it has rules for, or manifests with no supported kind | passes with a warning; **not an approval** |
| `UNAVAILABLE` | The service could not be reached and `on-service-error: warn` is set | passes with a warning; **not an approval** |

`WARN` (a finding below your `block-on` threshold) and `WAIVED` (a finding covered by a waiver) appear in the comment but do not change the verdict.

`fail-on-regression: 'false'` turns the step into report-only: nothing fails on a verdict. `fail-on-regression` and `post-pr-comment` must be exactly
`true` or `false`; anything else stops the step, so a typo cannot silently turn the gate into report-only. Without `plan-file` or `manifest-files` the Action
still answers from a built-in demo scenario and says so in a warning annotation.

### What leaves your runner

The Action runs on your runner and reduces the input before anything is sent:

* **Terraform plan:** only resources of the types QuietPhysics has rules for, and only the attributes those rules read (plus
  `after_unknown`). Everything else is dropped: variables, `prior_state`, planned values, outputs, provider configuration, other
  resource types, all other attributes, and all tags except `qp:role`.
* **Values you marked `sensitive`:** if an attribute the rules read (for example `ingress`, `cidr_blocks`, `policy`) carries a sensitive
  marker, the step **stops before sending anything** and names the attribute (never the resource or the value). A gate that cannot see a
  value cannot honestly approve it, and withholding it would let a change hide a risky value behind `sensitive()`. Remove `sensitive()`
  from what the rules read, or set `on-sensitive: send` to upload those values (the credential scrub below still applies).
  Sensitive markers on attributes the rules do not read never matter.
* **Kubernetes manifests:** only documents of the kinds QuietPhysics checks (workloads and RBAC objects), cut down to the fields the
  rules read. `Secret` and `ConfigMap` documents, environment variables, arguments, annotations, labels and images are not sent.
  The Action contains its own small YAML reader; YAML it cannot read with certainty (anchors, aliases, tags, multi-line flow
  collections, duplicate keys) stops the step with an error instead of being guessed at.
* **Source locations:** found on your runner by scanning your `.tf` files; only `file:line` is sent, never source text.
* **Credential-shaped values:** cloud access keys, private keys, tokens, JWTs, passwords in URLs, and this run's own API key and GitHub token are
  recognised in what would be sent (keys and values, also inside JSON policy text). If one is found, the step **stops before sending
  anything** and names the attribute and the kind (never the value). The Action never rewrites a value, because changing text the rules
  read could change the verdict. Remove the value from what the rules read. This is a best-effort check, not a guarantee that every
  credential format is recognised.
* Free text inside an attribute that is sent (for example a security-group description or a policy `Sid`) is sent as written.
* Nothing from your plan or manifests is printed to the job log.
* The service address must be `https` (plain `http` only for `localhost`), redirects are never followed, and keys or tokens containing
  spaces or control characters are refused, so your key is never sent anywhere you did not configure.
* The request is compressed above 16 KiB and must stay under 8 MiB, 5,000 resource changes and 64 levels of nesting; otherwise the step
  fails before sending anything and says what to shrink.

Not covered: Terraform Cloud plans without a local JSON file, and Helm and Kustomize (render them first).

---

## 🔑 Keyless authentication with GitHub OIDC (`auth: oidc`)

**Not enabled on the hosted service yet:** it currently accepts API keys only (`QP_AUTH_MODE=apikey`), so `auth: oidc` against the default `api-url` is rejected. This section describes the Action's side and a server that has OIDC switched on.

Instead of a stored API key, the Action can ask GitHub for a short-lived OIDC token and send it as `Authorization: Bearer <token>`. The server verifies it and identifies your repository's owner account from it; there is no secret to store or rotate. The token is masked in the log and is never written to an output, a file or the PR comment.

```yaml
permissions:
  contents: read          # actions/checkout
  pull-requests: write    # the PR comment
  id-token: write         # lets the job request an OIDC token

jobs:
  verify-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Evgsoft/quietPhysics-github-marketplace@main
        with:
          auth: oidc
          plan-file: plan.json
```

* **`id-token: write` is a job-wide permission.** Every step of that job, including third-party actions, can then request a token from GitHub for any audience. Grant it only to a job whose steps you trust, ideally a job of its own.
* **Audience.** The token is minted for `oidc-audience` (default: the host of `api-url`, lowercase, without scheme or port). It must equal `QP_OIDC_AUDIENCE` on the QuietPhysics server, or the token is rejected.
* **`auth: auto`** uses OIDC when the runner offers a token, else the `api-key` if you passed one, else the `on-no-token` rule. If OIDC is selected and the token request fails, the Action does not fall back to the key.
* **Forks.** Pull requests from forks do not receive an OIDC token (GitHub withholds it), and a job without `id-token: write` has none either. By default (`on-no-token: fail`) the step then fails with verdict `UNAVAILABLE` and says so. `on-no-token: skip` instead passes with a warning and verdict `SKIPPED`; that is **not an approval and not a gate**. For open-source repositories that take fork PRs, run the gate from a `pull_request_target` workflow that does not check out fork code, or from a workflow a maintainer triggers with an API key.
* `basic-auth-username` / `basic-auth-password` cannot be combined with OIDC.
* A server configuration problem (HTTP 503 `misconfigured`) always fails the step, whatever `on-service-error` says.

---

## Living with the check: advisory mode, a severity threshold and waivers

All three are off by default: a workflow that sets none of `advisory`, `block-on` and `waivers-file` behaves exactly as before.

* **`advisory: 'true'`** keeps the verdict and the comment truthful (a `BLOCKED` verdict is still written to the `verdict` output and the comment starts with an
  advisory banner on line 2) but the job exits 0 and `enforced` is `false`. Still failing the step: an unreachable service with `on-service-error: fail`, a
  rejected key (401/403), an invalid input, a credential-shaped value, `on-sensitive: fail`, and, with `auth: api-key`, an empty `QP_API_KEY` (fork and
  Dependabot pull requests have no secrets). **Recipe for a pilot:** `auth: auto` with `on-no-token: skip` (a run without a key or token ends `SKIPPED`,
  which is not an approval), `on-service-error: warn` for zero friction, and `on-sensitive: send` as the softer sensitive-value setting.
* **`block-on: high`** shows the two MEDIUM findings (a writable root filesystem, QP-K8S-003, and a secret without a customer-managed key, QP-SEC-001) as
  `WARN` instead of `FAIL`. `critical` also demotes HIGH. `INCONCLUSIVE` is never demoted. The server applies the threshold, so comment, counts and verdict agree.
* **Waivers** (`waivers-file: .quietphysics.yml`) accept a known finding for a limited time. Dates **must be quoted**:

  ```yaml
  waivers:
    - rule: QP-K8S-003
      resource: 'k8s:payments/Deployment/api'
      reason: "Legacy image writes /tmp; tracked in PLAT-412"
      expires: "2026-12-15"
  ```

  Exactly these four keys per entry; at most 50 entries and 64 KiB; `resource` is matched by exact string equality (ASCII, up to 300 characters; no wildcards, an
  address without an index does not cover its instances; unnamed manifests cannot be waived); a waiver is valid through the end of `expires` (UTC, server date);
  two entries for one rule and resource are both rejected; a waiver more than 90 days out is accepted and marked `long-lived waiver` in the comment. An
  `INCONCLUSIVE` finding is never waived. A waived finding is always listed, with its reason and date.

  **The waiver file is read from the repository default branch only**, through the GitHub API at the default branch's current head, with the `github-token`
  (`contents: read` is enough). A waiver added in a pull request therefore has no effect on that pull request and applies after it is merged, under the review
  rules of the default branch. A pull request that targets any other branch gets no waivers (the comment says so). Protect the file and your workflows with
  CODEOWNERS and a ruleset that requires code-owner review: `/.quietphysics.yml @org/security-reviewers` and `/.github/workflows/ @org/security-reviewers`.
  Residual risk: whoever can change the workflow in a pull request can remove the step or set `advisory`; closing that needs those rulesets.
  The Action assumes an unmodified runner. On the server waivers are advisory-grade (the server cannot verify where they came from); an operator can ignore them
  with `QP_POLICY_WAIVERS=off` (`block-on` still applies). GitHub Enterprise Server is not supported for the waiver fetch.

  **A waiver binds to the pair (rule, address), not to the content of the resource.** It covers every FAIL of that rule at that address, now and later, so a pull
  request that changes a waived resource (or adds a different violation of the same rule there) stays `WAIVED`. The `Waived until <date>: <reason>` line in the
  comment is how a reviewer notices; keep reasons specific and expiries short. The default branch is resolved through the branch-only API endpoint, so a tag
  named like the branch cannot redirect the fetch.

  **Waiver trust notes.** Anyone who can merge to the default branch controls the waiver text. Reasons are escaped, but bare autolinks (`https://...`,
  `www.`, `#123`, `org/repo#5`) survive and GitHub renders them, so review waiver reasons like any other text a reviewer sees. Test hook: the loader honours
  `QP_TEST_GITHUB_API_BASE` only together with `QP_TEST_ALLOW_HTTP_LOCALHOST=1` and a loopback `http` base; it is never mapped from `action.yml`. A workflow
  step that can write `GITHUB_ENV` can already read the token and edit the Action, so the hook adds no new capability, but it is a known tampering surface.

---

## ⚙️ Inputs reference

| Input | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| `api-key` | Your QuietPhysics Cloud API key (per-tenant, sent as `X-API-Key`). Needed with `auth: api-key`; not needed with `auth: oidc` | Only with `auth: api-key` | none - pass via `with:` from your own repo secret |
| `auth` | `api-key`, `oidc` (keyless, see below) or `auto` | No | `api-key` |
| `oidc-audience` | Audience of the OIDC token; must equal the server's `QP_OIDC_AUDIENCE` | No | the lowercase host of `api-url` (no scheme, no port) |
| `on-no-token` | `fail` or `skip` when no OIDC token is available (forks, missing `id-token: write`) | No | `fail` |
| `basic-auth-username` | Only if QuietPhysics gave you a separate shared closed-beta credential (see above) | No | none - pass via `with:`, same as `api-key` |
| `basic-auth-password` | See `basic-auth-username` | No | none |
| `api-url` | QuietPhysics Cloud endpoint | No | `https://tastjd22ug.us-east-1.awsapprunner.com/v1/evaluate` (no custom domain yet) |
| `scenario` | Invariant pack to evaluate (`all` or `1`-`8`) | No | `all` |
| `mode` | Evaluation mode: `pr-regression` or `baseline` | No | `pr-regression` |
| `fail-on-regression` | Exit non-zero on a detected regression | No | `true` |
| `post-pr-comment` | Post the rich attack-path breakdown to the PR | No | `true` |
| `github-token` | GitHub token for posting PR comments | No | `${{ github.token }}` |
| `on-service-error` | What to do when the API cannot answer after retries: `fail` or `warn` (see below) | No | `fail` |
| `plan-file` | Path to `terraform show -json` output; makes the gate judge your plan (see above) | No | none (built-in scenarios) |
| `manifest-files` | Kubernetes manifests (YAML or JSON): one glob pattern per line, e.g. `k8s/**/*.yaml` | No | none |
| `terraform-dir` | Root module directory, to find `file:line` of findings | No | `.` |
| `aws-account-ids` | Your own AWS account ids (comma separated, 12 digits each); lets the trust-policy rule tell your account from another | No | none |
| `on-inconclusive` | `warn` (job passes with a warning) or `fail` when a verdict is `INCONCLUSIVE` | No | `warn` |
| `on-sensitive` | `fail` (stop before sending when an attribute the rules read is marked sensitive) or `send` (upload those values) | No | `fail` |
| `block-on` | `any`, `high` or `critical`: the lowest severity that blocks (see "Living with the check") | No | `any` |
| `advisory` | `true` or `false` (empty = `false`): report the verdict without failing the job | No | `false` |
| `waivers-file` | Path of the waiver file in the repository, read from the default branch only (see below) | No | none |

Output `enforced`: `true` when this run could fail the job for the verdict it got (`fail-on-regression` is true, `advisory` is false, and an `INCONCLUSIVE` verdict only counts with `on-inconclusive: fail`), `false` otherwise, empty when no verdict was produced.

### When the QuietPhysics API is down: `on-service-error`

The client calls the API with bounded retries: up to 4 attempts, exponential backoff
with jitter, `Retry-After` honoured, and about two minutes in total, for HTTP 5xx,
HTTP 429, timeouts and connection failures. If it still gets no answer:

* `on-service-error: fail` (**default**): the step fails, so our outage blocks your merge.
  This is the strict choice and the current default.
* `on-service-error: warn`: the step passes with a warning annotation, writes the output
  `verdict=UNAVAILABLE` and a note in the job summary. **That is not an approval**: no
  check ran. Use it only if you would rather ship than be blocked by our outage, and keep
  your own review in place.

```yaml
      - uses: Evgsoft/quietPhysics-github-marketplace@main
        with:
          api-key: ${{ secrets.QP_API_KEY }}
          on-service-error: warn
```

Whatever you set, these always fail the step: a `BLOCKED` verdict, a missing, bad or
revoked key (HTTP 401/403), any other HTTP 4xx, and a response that is not a valid verdict.
`warn` only changes what happens when the service did not answer.

---

## 💬 Sample PR comment

This is the comment of a **built-in demo scenario** (no `plan-file`; the comment
then also carries a "Demo scenario result" line). The comment for your own plan
lists each finding with its rule id, resource, `file:line` when found, and the
fix suggestion of that rule; it does not print an attack path. The demo
scenario comment looks like this:

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

Appears the same way for both a full `scenario: 'all'` run and a
single-scenario run (`scenario: '1'`-`'8'`).

Re-running on the same PR (e.g. after pushing another commit) updates
this same comment in place rather than posting a new one each time.
