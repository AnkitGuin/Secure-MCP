import asyncio
import time
from typing import Any

import httpx2
from jsonschema import Draft202012Validator
from mcp import types
from mcp.shared.exceptions import MCPError
from opentelemetry import trace as telemetry
from prometheus_client import Counter, Histogram
from redis.exceptions import RedisError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from . import audit
from .config import Settings
from .db import (
    Approval,
    Connector,
    Customer,
    Document,
    Execution,
    Manifest,
    Membership,
    PrincipalRecord,
    TenantState,
    now,
    uid,
)
from .policy import OPA, Quota
from .registry import Registry, RegistryError
from .security import (
    Principal,
    address,
    canonical,
    digest,
    domain,
    has_sensitive,
    redact,
    review_cipher,
)
from .tools import RESULT_VALIDATORS, TOOLS, ToolSpec
from .wire import WireLimit, result

CALLS = Counter("securemcp_tool_calls_total", "Tool requests by bounded decision", ["effect"])
LATENCY = Histogram("securemcp_tool_decision_seconds", "Time until gateway decision")
TRACER = telemetry.get_tracer("securemcp.execution")
REMOTE_FAILURES = (
    ExceptionGroup,
    TimeoutError,
    httpx2.HTTPError,
    MCPError,
    RegistryError,
    WireLimit,
)
MESSAGES = {
    "TOOL_NOT_AVAILABLE": "This tool is unavailable for the current identity.",
    "INVALID_ARGUMENTS": "The request does not match the approved input schema.",
    "APPROVAL_REQUIRED": "An authorized reviewer must approve this exact action.",
    "APPROVAL_INVALID": "This approval cannot be used for this action.",
    "IDEMPOTENCY_CONFLICT": "This operation key already has a recorded execution.",
    "POLICY_ENGINE_UNAVAILABLE": "The authorization service is unavailable.",
    "RATE_LIMITED": "The request limit has been reached.",
    "UPSTREAM_UNAVAILABLE": "The connector could not complete the operation.",
    "UNKNOWN_REQUIRES_RECONCILIATION": "The operation may have taken effect. Review it before resubmitting.",
}


async def active_policy(db, tenant: str):
    from .db import PolicyVersion

    return await db.scalar(
        select(PolicyVersion)
        .join(TenantState, TenantState.active_policy == PolicyVersion.id)
        .where(TenantState.tenant == tenant, PolicyVersion.tenant == tenant)
    )


def policy_facts(p: Principal, spec: ToolSpec, *, phase: str, resource=None, parameters=None):
    risk = spec.risk
    if (
        phase == "execute"
        and spec.name == "send_message"
        and parameters
        and parameters.get("domain") == f"{p.tenant}.example"
        and not parameters.get("sensitive")
    ):
        risk = "R1"
    return {
        "phase": phase,
        "principal": {"tenant": p.tenant, "roles": sorted(p.roles), "scopes": sorted(p.scopes)},
        "tool": {"id": spec.id, "scope": spec.scope, "risk": risk, "trusted": True},
        "resource": resource or {},
        "parameters": parameters or {},
    }


async def resource_for(db, p: Principal, spec: ToolSpec, args: dict):
    facts = {
        "tenant": p.tenant,
        "accessible": True,
        "owner_match": True,
        "classification": "internal",
    }
    if not spec.resource:
        return facts, None
    model = Document if spec.resource == "document_id" else Customer
    stmt = select(model).where(model.tenant == p.tenant, model.id == args[spec.resource])
    if model is Customer:
        stmt = stmt.where(Customer.deleted.is_(False))
    row = await db.scalar(stmt)
    if row is None:
        return {**facts, "accessible": False}, None
    owner = f"{p.tenant}-support" if "demo_agent" in p.roles else p.name
    return {**facts, "owner_match": row.owner == owner, "classification": row.classification}, {
        "id": row.id,
        "owner": row.owner,
        "classification": row.classification,
    }


def normalize(spec: ToolSpec, args: dict):
    args = dict(args)
    params: dict[str, Any] = {}
    if spec.name == "send_message":
        args["to"], params["domain"] = address(args["to"])
        params["sensitive"] = has_sensitive(args["subject"] + "\n" + args["body"])
    if spec.name == "export_customers":
        args["destination"] = params["domain"] = domain(args["destination"])
        params["limit"] = args["limit"]
    return args, params


def public_schema(spec: ToolSpec, manifest: Manifest):
    raw = manifest.definition["inputSchema"]
    if not spec.write:
        return raw
    props = dict(raw["properties"])
    props["idempotency_key"] = props.pop("operation_id")
    return {
        **raw,
        "properties": props,
        "required": [
            "idempotency_key" if field == "operation_id" else field for field in raw["required"]
        ],
    }


class ExecutionService:
    def __init__(self, cfg: Settings, sessions, registry: Registry, opa: OPA, quota: Quota):
        self.cfg = cfg
        self.sessions = sessions
        self.registry = registry
        self.opa = opa
        self.quota = quota

    async def catalog(self, p: Principal, trace: str):
        async with self.sessions() as db:
            policy = await active_policy(db, p.tenant)
        if policy is None:
            return []
        specs = sorted(TOOLS.values(), key=lambda spec: spec.id)
        decisions = await asyncio.gather(
            *(
                self.opa.evaluate(policy_facts(p, spec, phase="discover"), policy.config)
                for spec in specs
            )
        )
        candidates = [
            spec
            for spec, decision in zip(specs, decisions, strict=True)
            if decision.effect == "allow"
        ]
        remote = {}
        for connector in sorted({spec.connector for spec in candidates}):
            try:
                remote[connector] = await self.registry.remote_catalog(connector, p)
            except REMOTE_FAILURES:
                continue
        catalog = []
        for spec in candidates:
            if spec.connector not in remote:
                continue
            manifest = await self.registry.approved(p.tenant, spec.id)
            if manifest and await self.registry.check(manifest, remote[spec.connector], p, trace):
                catalog.append(
                    types.Tool(
                        name=spec.id,
                        description=spec.description,
                        input_schema=public_schema(spec, manifest),
                    )
                )
        return catalog

    async def execute(
        self, p: Principal, trace: str, name: str, arguments: dict, approval_id: str | None
    ):
        with TRACER.start_as_current_span(
            "tool.execute", attributes={"securemcp.request_id": trace}
        ):
            return await self._execute(p, trace, name, arguments, approval_id)

    async def _execute(
        self, p: Principal, trace: str, name: str, arguments: dict, approval_id: str | None
    ):
        start = time.monotonic()
        spec = TOOLS.get(name)
        label = name if spec else "unknown_tool"
        details: dict[str, Any] = {}

        async def stop(code, *, effect="deny", **fields):
            duration = int((time.monotonic() - start) * 1000)
            async with self.sessions.begin() as db:
                await audit.append(
                    db,
                    p,
                    trace,
                    label,
                    effect,
                    code,
                    "blocked",
                    duration_ms=duration,
                    details=details | fields,
                )
            CALLS.labels(effect).inc()
            LATENCY.observe(duration / 1000)
            return result(
                {
                    "code": code,
                    "request_id": trace,
                    **fields,
                    "message": MESSAGES.get(code, "The requested action could not proceed."),
                },
                error=True,
            )

        try:
            if not await self.quota.admit(p.tenant, p.sub):
                return await stop("RATE_LIMITED")
        except (RedisError, TimeoutError):
            return await stop("RATE_CONTROL_UNAVAILABLE")
        if not spec:
            return await stop("TOOL_NOT_AVAILABLE")
        async with self.sessions() as db:
            policy = await active_policy(db, p.tenant)
        if not policy:
            return await stop("POLICY_ENGINE_UNAVAILABLE")
        details["policy"] = policy.id
        discover = await self.opa.evaluate(policy_facts(p, spec, phase="discover"), policy.config)
        if discover.effect != "allow":
            code = discover.reason_codes[0]
            return await stop(code if code == "POLICY_ENGINE_UNAVAILABLE" else "TOOL_NOT_AVAILABLE")
        manifest = await self.registry.approved(p.tenant, name)
        if not manifest or manifest.state != "APPROVED":
            return await stop("TOOL_NOT_AVAILABLE")
        details["manifest"] = manifest.version
        try:
            remote = await self.registry.remote_catalog(spec.connector, p)
        except REMOTE_FAILURES:
            return await stop("UPSTREAM_UNAVAILABLE")
        if not await self.registry.check(manifest, remote, p, trace):
            return await stop("TOOL_SCHEMA_DRIFT")
        if not Draft202012Validator(public_schema(spec, manifest)).is_valid(arguments):
            return await stop("INVALID_ARGUMENTS")
        try:
            args, parameters = normalize(spec, arguments)
            args_hash = digest(args)
        except (TypeError, ValueError):
            return await stop("INVALID_ARGUMENTS")
        async with self.sessions() as db:
            resource, effective = await resource_for(db, p, spec, args)
        facts = policy_facts(p, spec, phase="execute", resource=resource, parameters=parameters)
        details.update(args_hash=args_hash, facts=facts)
        decision = await self.opa.evaluate(facts, policy.config)
        if decision.effect == "deny":
            return await stop(decision.reason_codes[0])
        requires = decision.effect == "require_approval"
        binding = digest(
            [
                p.sub,
                p.tenant,
                manifest.fingerprint,
                manifest.version,
                policy.id,
                name,
                args_hash,
                effective,
                parameters,
                spec.risk,
                decision.approval_policy,
            ]
        )
        if requires and not approval_id:
            preview = {
                "arguments": redact(
                    {k: v for k, v in args.items() if k not in {"body", "note", "to", "subject"}}
                ),
                "target": {"recipient": "[redacted]", "domain": parameters["domain"]}
                if "to" in args
                else None,
                "content_digest": args_hash,
                "resource": effective and effective["id"],
                "risk": spec.risk,
                "policy_reason": decision.reason_codes[0],
                "category": decision.approval_policy,
            }
            async with self.sessions.begin() as db:
                row = Approval(
                    tenant=p.tenant,
                    requester=p.sub,
                    tool=name,
                    binding=binding,
                    preview=preview,
                    encrypted_arguments=review_cipher(self.cfg).encrypt(canonical(args)).decode(),
                    policy_id=policy.id,
                    fingerprint=manifest.fingerprint,
                    expires=now() + self.cfg.approval_ttl,
                )
                db.add(row)
                await db.flush()
                approval_id = row.id
                await audit.append(
                    db,
                    p,
                    trace,
                    name,
                    "require_approval",
                    "APPROVAL_REQUIRED",
                    "pending",
                    duration_ms=int((time.monotonic() - start) * 1000),
                    details=details | {"approval_id": approval_id},
                )
            CALLS.labels("require_approval").inc()
            LATENCY.observe(time.monotonic() - start)
            return result(
                {
                    "code": "APPROVAL_REQUIRED",
                    "request_id": trace,
                    "approval_id": approval_id,
                    "review_path": f"/approvals/{approval_id}",
                    "message": MESSAGES["APPROVAL_REQUIRED"],
                },
                error=True,
            )
        if approval_id and (not requires or not spec.write):
            return await stop("APPROVAL_INVALID")
        execution_id = uid() if spec.write else None
        if spec.write:
            try:
                failure = await self.reserve(
                    p,
                    trace,
                    spec,
                    args,
                    binding,
                    args_hash,
                    policy.id,
                    manifest,
                    approval_id,
                    execution_id,
                    details,
                    start,
                )
            except IntegrityError:
                failure = "IDEMPOTENCY_CONFLICT"
            if failure:
                return await stop(failure)
        else:
            async with self.sessions.begin() as db:
                await audit.append(
                    db,
                    p,
                    trace,
                    name,
                    "allow",
                    "POLICY_GRANTED",
                    "dispatching",
                    duration_ms=int((time.monotonic() - start) * 1000),
                    details=details,
                )
        CALLS.labels("allow").inc()
        LATENCY.observe(time.monotonic() - start)
        forwarded = {k: v for k, v in args.items() if k != "idempotency_key"}
        if execution_id:
            forwarded["operation_id"] = execution_id
        payload = None
        outcome, code = "SUCCEEDED", "POLICY_GRANTED"
        try:
            async with (
                asyncio.timeout(self.cfg.call_timeout),
                self.registry.slots,
                self.registry.client(spec.connector, p) as client,
            ):
                if (
                    client.server_info is None
                    or client.server_info.name != f"securemcp-{spec.connector}"
                ):
                    raise RegistryError("Connector identity mismatch")
                # Recheck on the dispatch connection as well as during authorization.
                tools = await client.list_tools(cache_mode="bypass")
                if tools.next_cursor or len(tools.tools) != len(
                    {item.name for item in tools.tools}
                ):
                    raise RegistryError("Unexpected connector catalog")
                current = {
                    item.name: item.model_dump(by_alias=True, exclude_none=True, mode="json")
                    for item in tools.tools
                }
                if not await self.registry.check(manifest, current, p, trace):
                    outcome, code = "FAILED_NO_EFFECT", "TOOL_SCHEMA_DRIFT"
                else:
                    response = await client.call_tool(spec.name, forwarded)
                    if response.is_error or response.result_type != "complete":
                        raise RegistryError("Upstream tool error")
                    payload = response.structured_content
                    if (
                        not isinstance(payload, dict)
                        or not RESULT_VALIDATORS[spec.name].is_valid(payload)
                        or len(canonical(payload)) > self.cfg.max_response
                    ):
                        raise WireLimit("Malformed upstream result")
        except REMOTE_FAILURES + (TypeError, ValueError):
            outcome = "UNKNOWN_REQUIRES_RECONCILIATION" if execution_id else "FAILED_NO_EFFECT"
            code = outcome if execution_id else "UPSTREAM_UNAVAILABLE"
        if payload is not None and "pii:read" not in p.scopes:
            payload = redact(payload)
        async with self.sessions.begin() as db:
            if execution_id:
                await db.execute(
                    update(Execution)
                    .where(Execution.tenant == p.tenant, Execution.id == execution_id)
                    .values(state=outcome)
                )
            if approval_id:
                await db.execute(
                    update(Approval)
                    .where(
                        Approval.tenant == p.tenant,
                        Approval.id == approval_id,
                        Approval.status == "RESERVED",
                    )
                    .values(status="CONSUMED" if outcome == "SUCCEEDED" else outcome)
                )
            await audit.append(
                db,
                p,
                trace,
                name,
                "allow" if outcome != "FAILED_NO_EFFECT" else "deny",
                code,
                outcome,
                duration_ms=int((time.monotonic() - start) * 1000),
                details=details | {"execution_id": execution_id, "approval_id": approval_id},
            )
        if outcome != "SUCCEEDED":
            return result(
                {
                    "code": code,
                    "request_id": trace,
                    "execution_id": execution_id,
                    "message": MESSAGES.get(code, "The operation could not proceed."),
                },
                error=True,
            )
        return result(
            {"request_id": trace, "data": payload, "provenance": "untrusted upstream content"}
        )

    async def reserve(
        self,
        p,
        trace,
        spec,
        args,
        binding,
        args_hash,
        policy_id,
        manifest,
        approval_id,
        execution_id,
        details,
        start,
    ):
        async with self.sessions.begin() as db:
            # A unique execution and conditional approval claim are committed together.
            if approval_id:
                # Take the approval row lock before the tenant audit lock, matching review order.
                approval = await db.scalar(
                    select(Approval)
                    .where(Approval.tenant == p.tenant, Approval.id == approval_id)
                    .with_for_update()
                )
                if (
                    not approval
                    or approval.requester != p.sub
                    or approval.binding != binding
                    or approval.status != "APPROVED"
                    or approval.expires <= now()
                ):
                    return "APPROVAL_INVALID"
                reviewer = await db.scalar(
                    select(Membership)
                    .join(PrincipalRecord)
                    .where(
                        Membership.sub == approval.reviewer,
                        Membership.tenant == p.tenant,
                        Membership.enabled.is_(True),
                        PrincipalRecord.enabled.is_(True),
                    )
                )
                if not reviewer or "security_admin" not in reviewer.roles:
                    return "APPROVAL_INVALID"
            state = await db.scalar(
                select(TenantState).where(TenantState.tenant == p.tenant).with_for_update()
            )
            approved = await db.get(Manifest, (p.tenant, spec.id, manifest.version))
            connector = await db.get(Connector, (p.tenant, spec.connector))
            if (
                not state
                or state.active_policy != policy_id
                or not approved
                or approved.state != "APPROVED"
                or not connector
                or not connector.enabled
            ):
                return "AUTHORIZATION_CHANGED"
            if approval_id:
                claim = await db.execute(
                    update(Approval)
                    .where(
                        Approval.tenant == p.tenant,
                        Approval.id == approval_id,
                        Approval.status == "APPROVED",
                        Approval.expires > now(),
                    )
                    .values(status="RESERVED")
                )
                if claim.rowcount != 1:
                    return "APPROVAL_INVALID"
            db.add(
                Execution(
                    id=execution_id,
                    tenant=p.tenant,
                    principal=p.sub,
                    tool=spec.id,
                    key=args["idempotency_key"],
                    digest=args_hash,
                    trace=trace,
                    approval_id=approval_id,
                    state="RESERVED",
                )
            )
            await audit.append(
                db,
                p,
                trace,
                spec.id,
                "allow",
                "POLICY_GRANTED",
                "dispatching",
                duration_ms=int((time.monotonic() - start) * 1000),
                details=details | {"approval_id": approval_id, "execution_id": execution_id},
            )
        return None
