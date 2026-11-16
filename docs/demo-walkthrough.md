# Six demo flows

Run `make demo` after the stack is ready. The console is available at [localhost:5173](http://localhost:5173). Each mutating demo uses a new idempotency key. The authorized export remains in the synthetic database for review.

| Demo | Identity and action | Expected evidence |
|---|---|---|
| Authorized read | Aurora support lists tools and reads `cus-a-01` | The result shows the assigned case and masked PII. The audit event links to the request. |
| Cross-tenant attempt | Aurora support requests `cus-b-01` | `RESOURCE_NOT_ACCESSIBLE` and no Borealis customer data. The same code applies to a missing ID. |
| Injected exfiltration | Support reads `doc-a-02`, attempts an external send; lead attempts an external export | `DESTINATION_BLOCKED`. The lab compares direct and protected export/outbox row counts in independent sandbox datasets. |
| Exact export approval | Aurora lead requests two records; Aurora security approves; lead retries | The changed quantity is rejected, the exact approved request creates one local export, and replay is rejected. |
| Policy what-if | Security stages a draft without export review and replays prior facts | Newly allowed results appear in the comparison. The test checks that business and audit tables remain unchanged for an unsaved replay. |
| Drift and policy outage | Run `TRUST-002` in Attack Lab, then inspect the connector tests | Drift prevents dispatch. The reapproval test verifies a compatible reviewed update. The OPA outage test verifies fail-closed execution. |

The [acceptance report](acceptance.md) records observed results. To inspect actual writes in an isolated native database, query `exports`, `messages`, and `upstream_operations` by tenant and operation ID. In the lab, per-case deltas appear directly in the UI and JSON report.

## Demo recording outline

1. Open Overview and show the tenant and live dependencies.
2. Open Attack Lab and compare the injected export across the three conditions.
3. Show the live approval queue before and after review, then show the replay denial in Security Events.
4. Compare an export policy draft in Policy Simulator, ending on the redacted audit integrity result.
