from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from redis.asyncio import Redis

from .security import SAFE_CODE, domain

ROLES = {"support_agent", "team_lead", "security_admin", "auditor", "demo_agent"}
SCOPES = {
    "mcp:tools",
    "tickets:read",
    "tickets:write",
    "docs:read",
    "messages:read",
    "messages:send",
    "customers:export",
    "customers:delete",
    "pii:read",
    "restricted:read",
    "console:access",
    "approvals:review",
}


ExportRole = Literal["team_lead", "support_agent", "demo_agent"]


def default_export_roles() -> list[ExportRole]:
    return ["team_lead"]


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    export_cap: int = Field(default=5, ge=1, le=20)
    external_domains: list[str] = Field(default_factory=list, max_length=8)
    export_roles: list[ExportRole] = Field(default_factory=default_export_roles, max_length=3)
    export_requires_approval: bool = True
    disabled_tools: list[str] = Field(default_factory=list, max_length=12)
    redact_pii: Literal[True] = True

    @field_validator("external_domains")
    @classmethod
    def normalized_domains(cls, values: list[str]) -> list[str]:
        return sorted({domain(value) for value in values})

    @field_validator("disabled_tools")
    @classmethod
    def known_tools(cls, values: list[str]) -> list[str]:
        from .tools import TOOLS

        if set(values) - set(TOOLS):
            raise ValueError("Unknown tool")
        return sorted(set(values))


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    effect: Literal["allow", "deny", "require_approval"]
    reason_codes: list[str] = Field(min_length=1, max_length=8)
    approval_policy: Literal["sensitive_export", "external_message"] | None
    obligations: list[Literal["AUDIT", "REDACT_PII"]] = Field(max_length=2)

    @field_validator("reason_codes")
    @classmethod
    def safe_codes(cls, values: list[str]):
        if any(not SAFE_CODE.fullmatch(v) for v in values):
            raise ValueError("Invalid code")
        return values

    def coherent(self):
        return "AUDIT" in self.obligations and (self.effect == "require_approval") == bool(
            self.approval_policy
        )


class OPA:
    def __init__(self, url: str, http: httpx.AsyncClient):
        self.url = url.rstrip("/")
        self.http = http

    async def evaluate(self, facts: dict[str, Any], config: dict[str, Any]) -> Decision:
        try:
            response = await self.http.post(
                f"{self.url}/v1/data/securemcp/decision",
                json={"input": {**facts, "config": config}},
            )
            response.raise_for_status()
            result = Decision.model_validate(response.json()["result"])
            if result.coherent():
                return result
        except (ValueError, TypeError, KeyError, ValidationError, httpx.HTTPError):
            pass
        return Decision(
            effect="deny",
            reason_codes=["POLICY_ENGINE_UNAVAILABLE"],
            approval_policy=None,
            obligations=["AUDIT"],
        )


class Quota:
    SCRIPT = """
    local n = redis.call('INCR', KEYS[1])
    if n == 1 then redis.call('EXPIRE', KEYS[1], 60) end
    return n
    """

    def __init__(self, redis: Redis, limit: int):
        self.redis = redis
        self.limit = limit

    async def admit(self, tenant: str, sub: str) -> bool:
        return (
            int(await self.redis.eval(self.SCRIPT, 1, f"smcp:quota:{tenant}:{sub}")) <= self.limit
        )
