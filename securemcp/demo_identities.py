IDENTITIES = {
    "aurora-support": ("00000000-0000-4000-8000-000000000001", "aurora", "support_agent"),
    "aurora-lead": ("00000000-0000-4000-8000-000000000002", "aurora", "team_lead"),
    "aurora-security": ("00000000-0000-4000-8000-000000000003", "aurora", "security_admin"),
    "borealis-support": ("00000000-0000-4000-8000-000000000004", "borealis", "support_agent"),
    "aurora-auditor": ("00000000-0000-4000-8000-000000000005", "aurora", "auditor"),
    "aurora-agent": ("00000000-0000-4000-8000-000000000006", "aurora", "demo_agent"),
    "aurora-reviewer": ("00000000-0000-4000-8000-000000000007", "aurora", "security_admin"),
}
ROLE_SCOPES = {
    "support_agent": "mcp:tools tickets:read tickets:write docs:read messages:read messages:send console:access",
    "team_lead": "mcp:tools tickets:read tickets:write docs:read messages:read messages:send customers:export restricted:read console:access",
    "security_admin": "console:access approvals:review",
    "auditor": "console:access",
    "demo_agent": "mcp:tools tickets:read docs:read",
}
