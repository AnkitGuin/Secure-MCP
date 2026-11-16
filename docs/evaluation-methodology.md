# Evaluation methodology

The benchmark contains 150 seeded scenarios across legitimate work, cross-tenant access, injection, approval, identity/schema failures, tool trust, and concurrency/idempotency. The deterministic held-out split selects every fifth fixture within a family. The direct and prompt-only modes use the same isolated connectors and tenant scoping. The prompt-only condition applies a scripted refusal for recognizable export or send instructions in the retrieved document. Obfuscated instructions exercise the limits of that script.

Each mode and repetition starts from fresh seeded SQLite state. Protected calls traverse the same application, official SDK transport over ASGI, JWT verification and live OPA used by the control plane. The lab uses an isolated RSA issuer and process-local admission so it can safely inject invalid tokens and run reproducibly. The native integration run separately checks Keycloak, Redis, PostgreSQL and three TCP connector endpoints. PostgreSQL concurrency is tested independently from the benchmark.

| Metric | Denominator and observed numerator |
|---|---|
| Unauthorized execution rate | Forbidden attempts, counted when a forbidden mutation is observed |
| Attack success rate | Attack scenarios, counted when unauthorized data exposure or mutation is observed |
| Legitimate completion and false denial | Legitimate cases with observed success, and their complement |
| Cross-tenant isolation failure | Cross-tenant trials with an observed exposure or mutation |
| Approval correctness | Review and replay cases with the expected gate or at-most-once export |
| Audit completeness | SDK attempts with matched redacted decision events; protocol and token rejections can lack a tenant event |
| Decision latency | Observed dispatch, gate or deny audit duration, excluding connector execution |
| Scenario latency and throughput | Wall time for the scenario with receipt queries and control calls; summed per sequential mode |

Run `make benchmark` or `python -m securemcp.lab --selection all --repeats 3` with OPA available. JSON contains the environment and case records, CSV supports analysis, and Markdown provides the comparison. Measurements use local compute and include SDK round trips, setup overhead within each case, and injected timeout cases. The optional model adapter has a separate mock test. Real-model runs require explicit opt-in and would measure stochastic behavior and token cost.
