# Policy rules

OPA receives server-derived identity, trusted tool attributes, normalized destination facts, and resource access facts. The same Rego decision is used by the execution service and the simulator. A policy result must include a known effect, nonempty stable reasons, an approval category when required, and audit obligations.

| Role | Primary capabilities |
|---|---|
| Support agent | Assigned case reads and updates, allowed document reads, permitted internal messaging |
| Team lead | Broader same-tenant reads, scoped writes, bounded exports with review |
| Security administrator | Registry and policy control, eligible approval reviews, audit and lab |
| Auditor | Redacted events, policy history and replay, benchmark results |
| Demo service principal | Assigned reads through explicit MCP scopes |

The deny rules check resource access, normalized exact domains, sensitive outbound markers, and export size. Destructive tools stay hidden and blocked. A missing role, scope or trusted manifest fails closed. Pattern matching covers synthetic structured markers and common textual identifiers and can be evaded by transformations.

Use `opa test policy -v`. To explore the effect of removing export review, stage a draft with `export_requires_approval` false, then replay a historical export in the simulator. The simulation reports what would change. Mandatory export review prevents activation of that draft. Validate an admissible draft before submitting it to a second security administrator for activation.
