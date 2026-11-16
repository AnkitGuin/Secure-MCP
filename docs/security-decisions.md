# Engineering decisions

| Decision | Reason and tradeoff |
|---|---|
| Pin MCP SDK 2.3.0 | The release implements modern stateless discovery and supports a verified legacy client. Upgrades require protocol and negative-path tests. |
| Filter catalogs by principal | The low-level SDK handler receives a per-request HTTP context. OPA evaluates discovery, and the SDK publishes private cache scope with zero TTL. |
| Verify issuer and audience before entitlement | A valid signature alone does not establish the token’s audience. Local membership narrows the scopes issued by Keycloak. Connector tokens use a separate signing key and audience per connector. |
| Use bounded policy data and versioned Rego | Operators can review small configuration changes without uploading arbitrary code. OPA failures and malformed decisions block execution. A second operator validates activation. |
| Bind and reserve approvals in PostgreSQL | The digest includes principal, tenant, canonical args, resource, tool, and policy snapshots. Approval row locking and an execution uniqueness constraint make concurrent redemption at most once. Timeouts leave a receipt-based reconciliation path. |
| Hash-chain sanitized audit evidence | A PostgreSQL trigger blocks ordinary writes to existing events. The chain detects mutation or removal against its stored head. Database administrators with full privileges can rewrite both. External checkpoints remain a deployment responsibility. |
| Isolate the baseline | Every comparison condition starts with synthetic fixtures and separate secrets. Scripted behavior provides reproducible backend outcomes. |
| Mask output and reject unsafe egress | Exact normalized domains, validated argument schemas, size limits, and pattern-based DLP reduce leakage. Pattern matching has limited coverage for encoding and paraphrases. |
