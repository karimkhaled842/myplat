# myplat — a tiny app with a full DevSecOps pipeline (SentinelSDLC)

`myplat` is a deliberately-vulnerable Flask "Tasks API" used to drive a complete
DevSecOps pipeline against **[SentinelSDLC](https://github.com/karimkhaled842)** (the ASPM/DevSecOps
hub at `/home/karim/appSecPlatform`) running **inside a kind cluster**, finishing with an
**ArgoCD** deploy of the app on a passing security gate.

The app is vulnerable *on purpose* — every scanner needs something real to find.

## Architecture

```
 source (this repo)
   │  make pipeline  ── sentinel CLI ──────────────► SentinelSDLC hub  (kind ns: sentinel)
   │   scan ▸ dedupe ▸ enrich ▸ prioritize ▸ gate        │  OCM operator (ns: sentinel-system)
   │                                                      │  reconciles SecurityPolicy/Placement CRs
   └─ gate GREEN ─► git push ─► ArgoCD ─► ns: myplat ─► trivy-k8s live scan ─► back into hub
```

## The seeded vulnerabilities (what each scanner catches)

| Location | Issue | Scanner / connector |
|---|---|---|
| `app.py` | SQL injection (f-string query), CWE-89 | semgrep, bandit |
| `app.py` | Hardcoded AWS key + API token, CWE-798 | gitleaks, bandit |
| `app.py` | Weak hash `md5`, CWE-327 | bandit, semgrep |
| `app.py` | `subprocess(..., shell=True)`, CWE-78 | bandit |
| `app.py` | Flask `debug=True`, bind 0.0.0.0 | bandit |
| `requirements.txt` | Outdated Flask/Jinja2/PyYAML/requests/urllib3 (many CVEs) | trivy, grype, SBOM→CVE |
| `Dockerfile` | EOL base, runs as root, no healthcheck | trivy config, checkov |
| `k8s/deployment.yaml` | No limits, runAsUser 0, allowPrivilegeEscalation | checkov, trivy-k8s |

A cross-tool **Log4Shell** is also imported (present in both the trivy and semgrep
samples) to prove **dedupe** and to trip the enforce gate.

## Prerequisites

- The kind cluster (`kind-kind`) with ArgoCD already installed (it is).
- The SentinelSDLC platform at `/home/karim/appSecPlatform`.
- An **empty public** GitHub repo `karimkhaled842/myplat` (ArgoCD pulls it credential-less).

## Run it

```bash
make hub         # build hub image -> kind load -> helm install (ns: sentinel) + postgres
make portforward # expose the in-cluster hub at http://127.0.0.1:8000
make ocm         # build operator -> kind load -> apply CRDs + operator (ns: sentinel-system)
make scanners    # bandit/semgrep/checkov (trivy/gitleaks/grype expected on PATH)
make pipeline    # the full 18-stage pipeline below (gate: fail -> remediate -> pass)
make deploy      # gate GREEN: push -> ArgoCD sync -> pods in ns:myplat -> trivy-k8s live scan
make console     # SentinelSDLC PatternFly console at http://127.0.0.1:5173
```

## Pipeline stages → SentinelSDLC feature

| # | Stage | Feature |
|---|---|---|
| 1 | Build & pytest | CI test gate |
| 2 | `tenants create/list` | multi-tenancy |
| 3 | `agent token/enroll/run` | hub-and-spoke spoke agent |
| 4 | `join --accept` | asset lifecycle |
| 5 | `scan` (semgrep/bandit/gitleaks/trivy/grype/checkov/nuclei) | connectors (SAST/secrets/SCA/IaC/DAST) |
| 6 | `import` zap/nuclei/sarif/grype/trivy/trivy-k8s samples | full connector coverage + dedupe |
| 7 | `sbom upload/show/export` | SBOM ⇄ CVE/VEX (CycloneDX + SPDX) |
| 8 | `policy apply` + `placement create` + `assetset create` | governance (inform/enforce, placement by label) |
| 9 | `findings list --min-risk` | dedupe / enrich / prioritize |
| 10 | `search --save` + `searches` + `/graphql` | Fleet Search DSL + GraphQL |
| 11 | `compliance status/controls` + `evidence snapshot/verify/export` | compliance + Ed25519-signed + PDF evidence |
| 12 | `findings set-status` / `risk-accept` / `ticket` | triage / SLA / ticketing |
| 13 | `findings fix` / `fix-pr` | AI auto-fix + emulated PR (deterministic) |
| 14 | `users create` + `auth whoami` + `audit list` | RBAC + immutable audit log |
| 15 | `report` sarif/junit/json/markdown | CI artifacts |
| 16 | `gate` (enforce) → risk-accept → re-gate | enforce gate blocks then clears |
| 17 | `ocm export` + live `kubectl get securitypolicies` | OCM CRDs + operator |
| 18 | image build → push → ArgoCD sync → trivy-k8s | live cluster deploy + runtime scan |

Artifacts land in `artifacts/`: `sentinel.sarif`, `report.xml`, `report.json`,
`summary.md`, `bom-cyclonedx.json`, `bom-spdx.json`, `evidence.md`, `evidence.pdf`,
`graphql-posture.json`, `ocm/*.yaml`, `trivy-k8s-live.json`.

## CI-as-code

`.github/workflows/sentinel.yml` runs the same scan→report→gate on a self-hosted
runner registered to this repo. Set repo secrets `SENTINEL_HUB_URL` and `SENTINEL_TOKEN`.
