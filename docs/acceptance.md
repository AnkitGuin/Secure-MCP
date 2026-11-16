# SecureMCP verification report

Fresh review: November 16, 2026, Windows 11, Python 3.13.3, Node 24.22.1, MCP Python SDK 2.3.0, PostgreSQL 16.13, and OPA 1.8.0. Results below replace the supplied acceptance claims for the current review. Supplied screenshots and the earlier native runbook remain historical artifacts.

## Checks performed

| Check | Result | Evidence / reproduction |
|---|---|---|
| Backend suite | PASS | **69 passed, 1 skipped**, `python -m scripts.test_stack -q -ra --tb=short`, using a temporary PostgreSQL database and live OPA. The only skip is POSIX permission enforcement on Windows. |
| Rego policy | PASS | `opa test policy -v`: 5 passed. |
| Python lint and format | PASS | `ruff check .` and `ruff format --check .`. |
| Typed service boundaries | PASS | `mypy --follow-imports=silent --ignore-missing-imports securemcp/config.py securemcp/security.py securemcp/policy.py securemcp/wire.py`. This is a bounded type check, not a whole-project typing claim. |
| Frontend reproducibility | PASS | Restored lockfile; `npm ci --offline --no-audit` completed from the populated cache. |
| Frontend lint and build | PASS | `npm run lint` and `npm run build`, including `tsc --noEmit`. |
| Python production dependencies | PASS | Frozen production requirements exported with `uv export`; `pip-audit --requirement ... --disable-pip --no-deps` reported no known vulnerabilities. |
| npm dependencies | PASS | `npm audit` reported zero vulnerabilities, including development packages, after pinning patched transitive `minimatch`. CI now audits at moderate severity. |
| Secret scan | PASS | Gitleaks 8.30.0 scanned the staged project with redaction and reported no leaks. |
| PostgreSQL migrations | PASS | Upgrade to head, `alembic check`, downgrade to 0001, re-upgrade, schema comparison, and full rollback. |
| Runtime database privileges | PASS | Docs cannot select customers; gateway cannot update customers or audit events; CRM can update customers; messaging can insert its outbox rows. |
| Append-only audit | PASS | PostgreSQL rejected a direct `UPDATE audit_events`, even under the test database owner. A privileged owner could still disable the trigger. |

For the backend command, set `SMCP_DATABASE_URL` to an administrator connection on a **dedicated local test PostgreSQL cluster** and `SMCP_OPA_URL` to the running policy service. The runner creates and removes its own database. See [native verification](native-verification.md) and the [README](../README.md) for environment setup.

## Defects fixed

- Missing frontend lockfile prevented reproducible `npm ci`, Docker builds, and CI dependency caching.
- Infinite/non-positive connector deadlines and invalid/excessive payload limits were accepted at startup. Settings now require finite positive deadlines up to 60 seconds and payload limits from 1 KiB to 1 MiB.
- Non-object OPA response envelopes could escape as type errors. They now produce the normal policy-unavailable denial.
- Malformed OIDC discovery/JWKS structures could break refreshes or discard the previous key cache. Refresh now validates structures and supported key identifiers before publishing a complete key snapshot.
- The isolated issuer opened a fresh HTTP client per policy request. Windows SSL-context setup caused concurrent discovery requests to exceed protocol deadlines. One client is now reused and closed with the sandbox lifetime.
- An npm development dependency advisory remained after ordinary compatible audit fixes. A scoped override selects patched `minimatch`, and CI audits development dependencies too.

The new boundary regressions reproduced 24 failures before correction; all 27 boundary cases now pass. Two further tests verify fail-closed behavior for exhausted and unavailable rate control.

## Security gates

| Gate | Result | Evidence |
|---|---|---|
| Modern and legacy MCP | PASS | Independent official SDK client over ASGI; 2026-07-28 and 2025-11-25, discovery, filtered listing and redacted read. |
| Header/body consistency | PASS | `test_header_mismatch`, no tool dispatch. |
| Invalid token and wrong audience | PASS | Six invalid-token variants reject access. |
| Cross-tenant read and hidden tools | PASS | Tenant/resource denial and guessed tool/scope tests. |
| Injected export and external message | PASS | Protected calls created no forbidden export artifact or outbox row. Direct baselines demonstrated the corresponding effects. |
| Legitimate scoped update | PASS | Persisted once; conflicting idempotency-key reuse rejected. |
| Exact-action approval and reviewer separation | PASS | Pending, expired, revoked, rejected, changed arguments, wrong requester, reviewer revocation, self-review and replay tests. |
| Concurrent approval redemption | PASS | Real PostgreSQL race: one successful redemption and one stored export. |
| Timeout safety | PASS | Ambiguous committed write is recorded for reconciliation and is not blindly retried. |
| OPA and rate-control failures | PASS | Dependency unavailability and exhausted quota did not dispatch a write. Redis failure was injected, rather than a live Redis outage. |
| Tool schema drift | PASS | Manifest lock, compatible reapproval, and incompatible input-schema rejection. |
| Policy activation and simulation | PASS | Independent activating operator, old-approval invalidation, and unsaved simulation with no execution effects. |
| Audit privacy and integrity | PASS | Redaction, encrypted argument reveal, retention, and integrity checks. |

## Fresh benchmark

Experiment `5c062279-82a0-48b5-98c5-f886c8494ea3` ran **150 scenarios × 3 modes × 3 repetitions = 1,350 executions**. All 135 legitimate protected cases completed; protected mode recorded zero unauthorized effects and zero unauthorized commits. Approval correctness and authenticated audit completeness were 1.0. Overall audit completeness was 0.95777 because some authentication/protocol rejections lack an authenticated tenant event.

Protected p95 decision latency was 145 ms and p95 scenario latency was 1,775.8 ms on this Windows run. Scenario timing includes SDK/control round trips and deliberately injected timeout cases. These figures are not production capacity measurements. The run occurred before the initial Git commit, so its recorded source commit is `unavailable`.

The [JSON, CSV and Markdown artifacts](../benchmark/reports/) contain the observed measurements. The [methodology](evaluation-methodology.md) explains the scripted prompt baseline and denominators. These synthetic results do not measure a real model's general resistance to prompt injection.

## Not verified locally and residual limits

- **NOT RUN:** complete Docker Compose bootstrap, real Keycloak smoke/demo, live Redis admission, authenticated Playwright login flows, and fresh dashboard screenshots. Docker Engine, Java/Keycloak, and Redis server were absent. The GitHub workflow is configured to run the full stack after publication; this file does not preclaim its result.
- The integration lab uses a generated RSA issuer, live OPA, in-process HTTP transport, and disposable SQLite snapshots. PostgreSQL concurrency, migrations and privileges were checked separately.
- No live LLM or external enterprise integration was tested. The optional adapter has a mock test.
- Database isolation uses scoped queries and service grants, without PostgreSQL RLS. External audit anchoring, deployment ingress limits, secret management, and independent penetration testing remain deployment work.
- A malicious upstream may retain its catalog while changing behavior. DLP is pattern-based. Passing this review does not establish that the software is flaw-free or production-ready.
