package securemcp

import rego.v1

normal := {
  "phase": "execute",
  "principal": {"tenant": "aurora", "roles": ["team_lead"], "scopes": ["mcp:tools", "customers:export"]},
  "tool": {"id": "crm__export_customers", "risk": "R2", "scope": "customers:export", "trusted": true},
  "config": {"export_cap": 5, "external_domains": [], "export_roles": ["team_lead"], "disabled_tools": [], "export_requires_approval": true},
  "resource": {"tenant": "aurora", "accessible": true, "owner_match": true, "classification": "internal"},
  "parameters": {"domain": "aurora.example", "limit": 2},
}

test_default_deny if {
    d := decision with input as {}
    d.effect == "deny"
}
test_export_requires_review if {
    d := decision with input as normal
    d.effect == "require_approval"
}
test_tenant_precedes_approval if {
  foreign := object.union(normal, {"resource": object.union(normal.resource, {"tenant": "borealis"})})
  d := decision with input as foreign
    d.reason_codes == ["RESOURCE_NOT_ACCESSIBLE"]
}
test_exact_domain_boundary if {
  changed := object.union(normal, {"parameters": {"domain": "aurora.example.attacker.test", "limit": 2}})
  d := decision with input as changed
    d.reason_codes == ["DESTINATION_BLOCKED"]
}
test_cap_blocks_export if {
  changed := object.union(normal, {"parameters": {"domain": "aurora.example", "limit": 6}})
  d := decision with input as changed
    d.reason_codes == ["EXPORT_CAP_EXCEEDED"]
}
