# Operator guide

1. Sign in to the console and confirm the displayed tenant and role. Review live dependency health on Overview.
2. Open Tool Registry to discover a connector and inspect any drift. Review the exact fingerprint and schema before approving a compatible change. Disable the connector during incident containment.
3. Open Approval Queue to inspect a pending operation. The default preview masks sensitive fields. Eligible reviewers may reveal the encrypted arguments with an audit trail. Reviewers record a rationale for approval, rejection, or revocation.
4. Investigate denied calls in Security Events using tool, principal, reason, time, or request ID. Export a redacted page and verify the tenant audit chain.
5. Run Attack Lab for a synthetic scenario. Compare reported mutations, outbox counts, and gateway decisions.
6. Stage a bounded draft in Policy Center. Use Policy Simulator to compare it against current decisions before a second administrator activates it.
7. For uncertain execution, use `POST /api/v1/executions/{id}/reconcile` with a rationale. An upstream receipt establishes an observed outcome. Preserve the operation key and inspect the result before considering a fresh request.
