package securemcp

import rego.v1

default decision := {"effect": "deny", "reason_codes": ["NOT_AUTHORIZED"], "approval_policy": null, "obligations": ["AUDIT"]}

has_role(role) if role in input.principal.roles

has_scope(scope) if scope in input.principal.scopes

operator if has_role("team_lead")

operator if has_role("support_agent")

operator if has_role("demo_agent")

grant if {
    input.tool.risk == "R0"
    operator
}

grant if {
    input.tool.risk == "R1"
    operator
}

grant if {
    input.tool.id == "messages__send_message"
    operator
}

grant if {
    input.tool.id == "crm__export_customers"
    some role in input.config.export_roles
    has_role(role)
}

base if {
    input.principal.tenant != ""
    has_scope("mcp:tools")
    has_scope(input.tool.scope)
    input.tool.trusted == true
    not input.tool.id in input.config.disabled_tools
    input.tool.risk != "R3"
    grant
}

deny_reason contains "RESOURCE_NOT_ACCESSIBLE" if {
    input.phase == "execute"
    input.resource.accessible != true
}

deny_reason contains "RESOURCE_NOT_ACCESSIBLE" if {
    input.phase == "execute"
    input.resource.tenant != input.principal.tenant
}

deny_reason contains "RESOURCE_NOT_ACCESSIBLE" if {
    input.phase == "execute"
    input.resource.owner_match == false
    not has_role("team_lead")
}

deny_reason contains "RESOURCE_NOT_ACCESSIBLE" if {
    input.phase == "execute"
    input.resource.classification == "restricted"
    not has_scope("restricted:read")
}

deny_reason contains "DESTINATION_BLOCKED" if {
    input.phase == "execute"
    input.tool.id in {"crm__export_customers", "messages__send_message"}
    input.parameters.domain != concat(".", [input.principal.tenant, "example"])
    not input.parameters.domain in input.config.external_domains
}

deny_reason contains "DATA_POLICY_BLOCKED" if {
    input.phase == "execute"
    input.tool.id == "messages__send_message"
    input.parameters.sensitive == true
}

deny_reason contains "EXPORT_CAP_EXCEEDED" if {
    input.phase == "execute"
    input.tool.id == "crm__export_customers"
    input.parameters.limit > input.config.export_cap
}

approval_category := "sensitive_export" if {
    input.tool.id == "crm__export_customers"
    input.config.export_requires_approval == true
}

approval_category := "external_message" if {
    input.tool.id == "messages__send_message"
    input.parameters.domain != concat(".", [input.principal.tenant, "example"])
}

decision := {"effect": "allow", "reason_codes": ["DISCOVERY_GRANTED"], "approval_policy": null, "obligations": ["AUDIT"]} if {
    input.phase == "discover"
    base
}

decision := {"effect": "deny", "reason_codes": sort(deny_reason), "approval_policy": null, "obligations": ["AUDIT"]} if {
    input.phase == "execute"
    base
    count(deny_reason) > 0
}

decision := {"effect": "require_approval", "reason_codes": ["SENSITIVE_REVIEW_REQUIRED"], "approval_policy": approval_category, "obligations": ["AUDIT", "REDACT_PII"]} if {
    input.phase == "execute"
    base
    count(deny_reason) == 0
    approval_category
}

decision := {"effect": "allow", "reason_codes": ["POLICY_GRANTED"], "approval_policy": null, "obligations": ["AUDIT", "REDACT_PII"]} if {
    input.phase == "execute"
    base
    count(deny_reason) == 0
    not approval_category
}
