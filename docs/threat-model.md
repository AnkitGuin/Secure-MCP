# Threat model

## Assets and boundaries

The main assets are customer records, document content, connector credentials, approval authority, policy versions, and the audit chain. Threat actors include malicious document authors, manipulated agents, tenant users, changed or compromised tools, and privileged infrastructure operators. The [architecture](architecture.md) identifies the identity, policy, connector, and operator boundaries.

| Threat and precondition | Invariant | Mitigation and detection | Residual risk and evidence |
|---|---|---|---|
| Untrusted document proposes export or external message | Tool output cannot authorize an action | Tenant, scope, domain, DLP and approval gates; local artifacts and outbox counted | Content may still alter model plans. `INJECT-001`, `INJECT-002`, `test_poison_has_no_effect` |
| Attacker presents a signed token for another service | Gateway audience and issuer must match | Pinned discovery, RS256, JWKS cache, expiry and membership checks | Revocation outside the app is bounded by access-token lifetime. `test_invalid_access_token` |
| Guessed cross-tenant IDs and client-supplied owner | Tenant and ownership derive from trusted state | Scoped lookup and upstream tenant filtering; generic inaccessible error | Time-based side-channel resistance has no formal proof. `test_cross_tenant_customer_read` |
| Tool replacement, malicious catalog or schema drift | Only pinned definitions execute | Stable names, live fingerprints, drift lock, approved version history | A malicious server may preserve its catalog while changing behavior. `test_tool_drift_lock_and_reapproval` |
| SSRF, rebinding or redirected endpoint | Credentials reach one preconfigured connector address | IP literals, explicit local private HTTP mode, verified TLS otherwise, no redirects, no proxies or compression | Network administrators must enforce routing and trusted certificate controls. `test_redirect_and_response_limit` |
| Direct bypass or confused deputy | Agents use only the authorized gateway path | Private network, isolated signing keys, per-connector credential audience, database grants | An independently privileged network caller or compromised gateway is outside this guarantee. `make smoke` and Compose config |
| Approval swap, replay, double dispatch or timeout | One exact reviewed action may commit once | Signed identity, binding digest, expiry, distinct reviewer, row lock, unique reservation and receipt | A crashed process can leave a reservation for operator reconciliation. `test_approval_invalid`, PostgreSQL race, timeout test |
| Unsafe policy activation | Candidate evaluation cannot invoke tools | Bounded DTO, tenant version history, second administrator, side-effect-free replay | Two authorized admins can adjust allowed destinations and thresholds within validated bounds. `test_policy_activation_requires_second_operator_and_invalidates_old_approval` |
| Audit tampering | Ordinary app roles append and verify | PostgreSQL trigger, narrow grants, integrity chain, selective fields | Database owner can disable triggers or rewrite anchors. Native migration checks and integrity test |
| Browser injection or cross-origin control | Untrusted text stays text, protected APIs require bearer | React rendering, PKCE state, in-memory bearer, strict origin and CSP | A compromised JavaScript bundle or IdP can steal active credentials. Browser and origin tests |
| Resource exhaustion and connector loss | Failed dependencies cannot permit writes | Request and response limits, timeouts, Redis quotas, bounded connector concurrency, readiness checks | Distributed volumetric DoS requires ingress rate limits. `test_opa_unavailable` and transport limit test |
