# SecureMCP

SecureMCP puts an independent authorization boundary between agents and enterprise tools. The gateway authenticates an MCP caller, resolves a pinned tool and tenant-scoped resource, evaluates a deterministic OPA policy, and records the resulting decision. Sensitive writes can require a human review bound to the exact action. The local CRM, document store, and messaging outbox use synthetic data and persist real changes.

**NO REAL CUSTOMER DATA.** The demo outbox stays local. The attack lab uses disposable datasets and separate credentials.

## Run locally

Prerequisites are Docker Engine with Compose v2, Python 3.12 or newer, and `uv`. Node 24 is needed for frontend development and browser tests.

```sh
make bootstrap
make smoke
make demo
```

Open [the console](http://localhost:5173) and sign in through Keycloak. `make bootstrap` generates the demo password and starts the full stack. Read the `DEMO_PASSWORD` entry from the local `.local/secrets.env` file. Keycloak is on [localhost:8080](http://localhost:8080). MCP clients connect to [localhost:5173/mcp](http://localhost:5173/mcp).

| Identity | Use |
|---|---|
| `aurora-support` | Reads assigned cases and updates status |
| `aurora-lead` | Requests a bounded export |
| `aurora-security` | Reviews exports and stages policy drafts |
| `aurora-reviewer` | Independently activates validated drafts |
| `aurora-auditor` | Reads tenant-scoped, redacted events and benchmark reports |
| `borealis-support` | Exercises cross-tenant isolation |
| `securemcp-agent` | OAuth client-credentials service account with read-only tool permissions |

### PowerShell

```powershell
python -m scripts.provision
docker compose --env-file .local/secrets.env up --build --wait --wait-timeout 240
Get-Content .local/secrets.env | ForEach-Object {
  $key, $value = $_ -split '=', 2
  [Environment]::SetEnvironmentVariable($key, $value, 'Process')
}
uv run --frozen python -m scripts.client smoke
uv run --frozen python -m scripts.client demo
```

### Verification commands

| Command | Checks |
|---|---|
| `make smoke` | Keycloak tokens, MCP 2026-07-28 discovery, MCP 2025-11-25 compatibility, filtered tools, and redacted customer read |
| `make demo` | Authorized read, cross-tenant denial, injection, approval and replay, policy simulation, and connector drift |
| `make test` | Backend suite with live OPA and a disposable PostgreSQL database |
| `make test-security` | Targeted tenant, token, approval, and protocol tests |
| `make test-e2e` | Keycloak login, console, attack lab, and role checks after installing Playwright Chromium |
| `make benchmark` | 150 deterministic scenarios in three conditions, repeated three times |
| `make lint` | Python lint and formatting, frontend lint and TypeScript build |
| `make down` | Stops local services and retains PostgreSQL data |

For browser tests, run `npm ci` and `npx playwright install chromium` in `frontend/` first. For native development without Docker, follow [the native verification runbook](docs/native-verification.md).

## Repository map

| Path | Contents |
|---|---|
| `securemcp/` | FastAPI control plane, official MCP SDK v2 gateway and connector apps, token verification, execution, approval and audit services |
| `policy/` | OPA Rego policy and unit tests |
| `migrations/` | Reversible Alembic schema and append-only audit trigger |
| `frontend/` | React and TypeScript console, PKCE login, Playwright tests |
| `benchmark/reports/` | Versioned scenarios and measured output |
| `tests/` | Protocol, security, database, and property tests |
| `infra/` | Container builds |
| `instructions.md` | Original project specification |

## Evidence and scope

The [current verification report](docs/acceptance.md) records the November 16, 2026 Windows review, security regressions, PostgreSQL checks, and validation limits. Frontend dependencies are locked; CI audits development dependencies as well as production packages.

Read the [acceptance report](docs/acceptance.md) for observed results, the [demo walkthrough](docs/demo-walkthrough.md) for the six flows, and the [evaluation methodology](docs/evaluation-methodology.md) for the benchmark denominators. The deterministic prompt condition uses scripted behavior and measures the consequence of tool proposals. Real model susceptibility requires a separate experiment. The optional model adapter has a mock test and requires an explicit API key and model to run.

Review the [threat model](docs/threat-model.md) and [deployment notes](docs/deployment-hardening.md) before using this design with real integrations. Licensed under the [MIT License](LICENSE).
