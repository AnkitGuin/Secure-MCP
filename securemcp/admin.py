import asyncio
import json
from collections import Counter
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, func, or_, select, update
from starlette.responses import JSONResponse

from . import audit
from .config import CONNECTORS
from .db import (
    Approval,
    ApprovalReview,
    Audit,
    BenchmarkResult,
    BenchmarkRun,
    Connector,
    Execution,
    Manifest,
    Membership,
    PolicyGrant,
    PolicyVersion,
    PrincipalRecord,
    Simulation,
    TenantState,
    UpstreamOperation,
    now,
)
from .execution import REMOTE_FAILURES, active_policy, policy_facts
from .policy import ROLES, PolicyConfig
from .security import Principal, digest, redact, review_cipher
from .tools import TOOLS

router = APIRouter(prefix="/api/v1")


class APIError(Exception):
    def __init__(self, code: str, status=400):
        self.code = code
        self.status = status


def principal(request: Request) -> Principal:
    p = request.state.principal
    if "console:access" not in p.scopes:
        raise APIError("CONSOLE_SCOPE_REQUIRED", 403)
    return p


def operator(p: Annotated[Principal, Depends(principal)]):
    if "security_admin" not in p.roles:
        raise APIError("FORBIDDEN", 403)
    return p


def auditor(p: Annotated[Principal, Depends(principal)]):
    if not p.roles.intersection({"security_admin", "auditor"}):
        raise APIError("FORBIDDEN", 403)
    return p


Actor = Annotated[Principal, Depends(principal)]
Operator = Annotated[Principal, Depends(operator)]
Auditor = Annotated[Principal, Depends(auditor)]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Rationale(Input):
    rationale: str = Field(min_length=8, max_length=300)


class NewConnector(Input):
    connector: Literal["crm", "docs", "messages"]


class ManifestReview(Rationale):
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")


class Draft(Rationale):
    config: PolicyConfig


class SimulationInput(Input):
    candidate: str = Field(max_length=36)
    tool: str | None = Field(None, max_length=96)
    role: str | None = Field(None, max_length=32)
    risk: Literal["R0", "R1", "R2", "R3"] | None = None
    limit: int = Field(60, ge=1, le=100)
    save: bool = False


class MembershipInput(Rationale):
    enabled: bool
    roles: list[str] = Field(min_length=1, max_length=4)


class LabInput(Input):
    scenario: str = Field("all", max_length=40)


def row_view(row, fields: str) -> dict:
    return {field: getattr(row, field) for field in fields.split()}


async def scoped(db, model, tenant: str, identifier: str, *, lock=False):
    stmt = select(model).where(model.tenant == tenant, model.id == identifier)
    row = await db.scalar(stmt.with_for_update() if lock else stmt)
    if row is None:
        raise APIError("NOT_FOUND", 404)
    return row


def policy_view(row):
    return row_view(
        row, "id tenant config checksum author reason state created activated validated"
    )


def approval_view(row):
    data = row_view(
        row, "id tenant requester tool preview policy_id status created expires reviewer"
    )
    if row.status in {"PENDING", "APPROVED"} and row.expires <= now():
        data["status"] = "EXPIRED"
    return data


def runtime(request: Request):
    return request.app.state.runtime


@router.get("/me")
async def me(p: Actor):
    return {
        "sub": p.sub,
        "name": p.name,
        "tenant": p.tenant,
        "roles": sorted(p.roles),
        "scopes": sorted(p.scopes),
    }


@router.get("/overview")
@router.get("/metrics/summary")
async def overview(request: Request, p: Actor, hours: Annotated[int, Query(ge=1, le=168)] = 24):
    rt = runtime(request)
    recent_cutoff = now() - hours * 3600
    async with rt.sessions() as db:
        decisions = (
            await db.scalars(
                select(Audit)
                .where(
                    Audit.tenant == p.tenant,
                    Audit.occurred >= recent_cutoff,
                    Audit.outcome.in_(("blocked", "pending", "dispatching")),
                )
                .order_by(Audit.seq.desc())
                .limit(2000)
            )
        ).all()
        active = await db.scalar(
            select(func.count())
            .select_from(Connector)
            .where(Connector.tenant == p.tenant, Connector.enabled.is_(True))
        )
        connectors = (
            await db.scalars(
                select(Connector.id).where(
                    Connector.tenant == p.tenant, Connector.enabled.is_(True)
                )
            )
        ).all()
    times = sorted(event.duration_ms for event in decisions)
    effects = Counter(event.effect for event in decisions)
    series = Counter((event.occurred // 3600) * 3600 for event in decisions)
    risks = Counter(
        event.details.get("facts", {}).get("tool", {}).get("risk", "unknown")
        for event in decisions
        if event.effect != "allow"
    )

    async def check_connector(connector):
        try:
            await rt.registry.remote_catalog(connector, p)
            return connector, True
        except REMOTE_FAILURES:
            return connector, False

    health, connector_health = await asyncio.gather(
        rt.health(), asyncio.gather(*(check_connector(connector) for connector in connectors))
    )
    health.update(dict(connector_health))
    return {
        "total": len(decisions),
        "counts": effects,
        "active_connectors": active,
        "latency": {
            "p50": times[(len(times) - 1) // 2] if times else 0,
            "p95": times[int((len(times) - 1) * 0.95)] if times else 0,
        },
        "series": [{"time": ts, "count": series[ts]} for ts in sorted(series)],
        "risk_counts": risks,
        "health": health,
        "latest": [
            audit.view(event)
            if p.roles.intersection({"security_admin", "auditor"})
            else row_view(event, "id tool effect reason occurred")
            for event in decisions[:8]
        ],
    }


@router.get("/connectors")
async def connectors(request: Request, p: Actor):
    async with runtime(request).sessions() as db:
        rows = (
            await db.scalars(
                select(Connector).where(Connector.tenant == p.tenant).order_by(Connector.id)
            )
        ).all()
    return [row_view(row, "id enabled last_discovery") for row in rows]


@router.get("/connectors/{identifier}")
async def connector_detail(request: Request, p: Actor, identifier: str):
    async with runtime(request).sessions() as db:
        row = await scoped(db, Connector, p.tenant, identifier)
    return row_view(row, "id enabled last_discovery") | {
        "transport": "Streamable HTTP",
        "endpoint": "pinned private /mcp",
    }


@router.post("/connectors", status_code=201)
async def register_connector(request: Request, p: Operator, body: NewConnector):
    rt = runtime(request)
    async with rt.sessions.begin() as db:
        row = await db.get(Connector, (p.tenant, body.connector))
        if row is not None:
            raise APIError("ALREADY_REGISTERED", 409)
        db.add(Connector(tenant=p.tenant, id=body.connector, enabled=False))
        await audit.append(
            db, p, request.state.trace, body.connector, "allow", "CONNECTOR_REGISTERED", "recorded"
        )
    return {"id": body.connector, "enabled": False}


@router.post("/connectors/{identifier}/{action}")
async def connector_action(
    request: Request, p: Operator, identifier: str, action: Literal["discover", "disable", "enable"]
):
    rt = runtime(request)
    if identifier not in CONNECTORS:
        raise APIError("NOT_FOUND", 404)
    if action in {"discover", "enable"}:
        try:
            catalog = await rt.registry.discover(identifier, p, request.state.trace)
        except REMOTE_FAILURES as error:
            raise APIError("UPSTREAM_UNAVAILABLE", 503) from error
        for spec in TOOLS.values():
            if spec.connector == identifier:
                manifest = await rt.registry.approved(p.tenant, spec.id)
                if manifest:
                    await rt.registry.check(manifest, catalog, p, request.state.trace)
    async with rt.sessions.begin() as db:
        row = await scoped(db, Connector, p.tenant, identifier)
        if action != "discover":
            row.enabled = action == "enable"
        await audit.append(
            db,
            p,
            request.state.trace,
            identifier,
            "allow",
            "CONNECTOR_" + action.upper(),
            "recorded",
        )
    return {"id": identifier, "enabled": row.enabled, "last_discovery": row.last_discovery}


def manifest_view(manifest):
    return row_view(manifest, "tool connector version fingerprint state definition created")


@router.get("/tools")
async def tools(request: Request, p: Actor):
    rt = runtime(request)
    if not p.roles.intersection({"security_admin", "auditor"}):
        return [
            {"tool": tool.name, "definition": tool.model_dump(by_alias=True), "state": "APPROVED"}
            for tool in await rt.execution.catalog(p, request.state.trace)
        ]
    async with rt.sessions() as db:
        rows = (
            await db.scalars(
                select(Manifest)
                .where(Manifest.tenant == p.tenant)
                .order_by(Manifest.tool, Manifest.version.desc())
            )
        ).all()
    current = {}
    for row in rows:
        current.setdefault(
            row.tool,
            manifest_view(row) | {"risk": TOOLS[row.tool].risk, "scope": TOOLS[row.tool].scope},
        )
    return list(current.values())


@router.get("/tools/{identifier}")
async def tool_detail(request: Request, p: Auditor, identifier: str):
    rt = runtime(request)
    async with rt.sessions() as db:
        row = await db.scalar(
            select(Manifest)
            .where(Manifest.tenant == p.tenant, Manifest.tool == identifier)
            .order_by(Manifest.version.desc())
            .limit(1)
        )
    if row is None:
        raise APIError("NOT_FOUND", 404)
    info = manifest_view(row) | {"risk": TOOLS[identifier].risk, "scope": TOOLS[identifier].scope}
    try:
        remote = await rt.registry.remote_catalog(row.connector, p)
        candidate = remote.get(TOOLS[identifier].name)
        if candidate and (row.state == "DRIFTED" or digest(candidate) != row.fingerprint):
            info.update(candidate=candidate, candidate_fingerprint=digest(candidate))
    except REMOTE_FAILURES:
        info["connector_unavailable"] = True
    return info


@router.post("/tools/{identifier}/approve-manifest")
async def approve_manifest(request: Request, p: Operator, identifier: str, body: ManifestReview):
    rt = runtime(request)
    spec = TOOLS.get(identifier)
    if spec is None:
        raise APIError("NOT_FOUND", 404)
    try:
        remote = await rt.registry.remote_catalog(spec.connector, p)
        current = remote[spec.name]
        schema = current["inputSchema"]
        Draft202012Validator.check_schema(schema)
    except REMOTE_FAILURES + (KeyError, ValueError) as error:
        raise APIError("INVALID_UPSTREAM_MANIFEST", 409) from error
    # Demo adapters use a fixed safe argument contract. Descriptions and annotations can be reapproved.
    if (
        digest(current) != body.fingerprint
        or schema != spec.wire().input_schema
        or current.get("outputSchema") is not None
    ):
        raise APIError("UNSUPPORTED_OR_CHANGED_MANIFEST", 409)
    async with rt.sessions.begin() as db:
        await db.scalar(select(TenantState).where(TenantState.tenant == p.tenant).with_for_update())
        version = (
            await db.scalar(
                select(func.max(Manifest.version)).where(
                    Manifest.tenant == p.tenant, Manifest.tool == identifier
                )
            )
            or 0
        )
        row = Manifest(
            tenant=p.tenant,
            tool=identifier,
            connector=spec.connector,
            version=version + 1,
            definition=current,
            fingerprint=body.fingerprint,
            state="APPROVED",
        )
        db.add(row)
        await audit.append(
            db,
            p,
            request.state.trace,
            identifier,
            "allow",
            "MANIFEST_APPROVED",
            "recorded",
            details={"version": row.version, "reason": redact(body.rationale)},
        )
    return manifest_view(row)


@router.get("/policies")
async def policies(request: Request, p: Auditor):
    async with runtime(request).sessions() as db:
        rows = (
            await db.scalars(
                select(PolicyVersion)
                .where(PolicyVersion.tenant == p.tenant)
                .order_by(PolicyVersion.created.desc())
                .limit(100)
            )
        ).all()
    return [policy_view(row) for row in rows]


@router.get("/policies/{identifier}")
async def policy_detail(request: Request, p: Auditor, identifier: str):
    async with runtime(request).sessions() as db:
        return policy_view(await scoped(db, PolicyVersion, p.tenant, identifier))


@router.post("/policies/drafts", status_code=201)
async def stage(request: Request, p: Operator, body: Draft):
    config = body.config.model_dump()
    async with runtime(request).sessions.begin() as db:
        row = PolicyVersion(
            tenant=p.tenant,
            config=config,
            checksum=digest(config),
            author=p.sub,
            reason=redact(body.rationale),
            state="DRAFT",
        )
        db.add(row)
        await db.flush()
        for role in config["export_roles"]:
            db.add(
                PolicyGrant(
                    tenant=p.tenant, policy_id=row.id, role=role, tool="crm__export_customers"
                )
            )
        await audit.append(
            db,
            p,
            request.state.trace,
            "policy",
            "allow",
            "POLICY_STAGED",
            "recorded",
            details={"policy": row.id, "checksum": row.checksum},
        )
    return policy_view(row)


@router.post("/policies/drafts/{identifier}/validate")
async def validate(request: Request, p: Operator, identifier: str):
    rt = runtime(request)
    async with rt.sessions.begin() as db:
        await db.scalar(select(TenantState).where(TenantState.tenant == p.tenant).with_for_update())
        row = await scoped(db, PolicyVersion, p.tenant, identifier, lock=True)
        if row.state != "DRAFT":
            raise APIError("POLICY_NOT_DRAFT", 409)
        cfg = PolicyConfig.model_validate(row.config)
        if not cfg.export_requires_approval:
            raise APIError("MANDATORY_EXPORT_REVIEW", 409)
        facts = policy_facts(p, TOOLS["crm__delete_customer"], phase="discover")
        verdict = await rt.opa.evaluate(facts, cfg.model_dump())
        if verdict.effect != "deny" or "POLICY_ENGINE_UNAVAILABLE" in verdict.reason_codes:
            raise APIError("POLICY_VALIDATION_FAILED", 409)
        row.validated = True
        await audit.append(
            db,
            p,
            request.state.trace,
            "policy",
            "allow",
            "POLICY_VALIDATED",
            "recorded",
            details={"policy": row.id},
        )
    return policy_view(row)


@router.post("/policies/drafts/{identifier}/activate")
async def activate(request: Request, p: Operator, identifier: str, body: Rationale):
    rt = runtime(request)
    async with rt.sessions.begin() as db:
        state = await db.scalar(
            select(TenantState).where(TenantState.tenant == p.tenant).with_for_update()
        )
        row = await scoped(db, PolicyVersion, p.tenant, identifier, lock=True)
        if not row.config.get("export_requires_approval"):
            raise APIError("MANDATORY_EXPORT_REVIEW", 409)
        if row.author == p.sub or not row.validated or row.state != "DRAFT":
            raise APIError("POLICY_REVIEW_REQUIRED", 409)
        previous = await scoped(db, PolicyVersion, p.tenant, state.active_policy)
        previous.state = "RETIRED"
        row.state, row.activated = "ACTIVE", now()
        state.active_policy = row.id
        await audit.append(
            db,
            p,
            request.state.trace,
            "policy",
            "allow",
            "POLICY_ACTIVATED",
            "recorded",
            details={"policy": row.id, "reason": redact(body.rationale)},
        )
    return policy_view(row)


@router.post("/policies/simulate")
async def simulate(request: Request, p: Auditor, body: SimulationInput):
    rt = runtime(request)
    if body.save and "security_admin" not in p.roles:
        raise APIError("FORBIDDEN", 403)
    async with rt.sessions() as db:
        current = await active_policy(db, p.tenant)
        candidate = await scoped(db, PolicyVersion, p.tenant, body.candidate)
        events = (
            await db.scalars(
                select(Audit).where(Audit.tenant == p.tenant).order_by(Audit.seq.desc()).limit(500)
            )
        ).all()
    unique = {}
    for event in events:
        facts = event.details.get("facts")
        if facts and (not body.tool or event.tool == body.tool):
            if (not body.role or body.role in facts["principal"]["roles"]) and (
                not body.risk or body.risk == facts["tool"]["risk"]
            ):
                unique.setdefault(event.trace, (event, facts))
    cases = list(unique.values())[: body.limit]
    results = []
    for offset in range(0, len(cases), 8):
        batch = cases[offset : offset + 8]

        async def compare(event, facts):
            left, right = await asyncio.gather(
                rt.opa.evaluate(facts, current.config), rt.opa.evaluate(facts, candidate.config)
            )
            if "POLICY_ENGINE_UNAVAILABLE" in left.reason_codes + right.reason_codes:
                raise APIError("POLICY_ENGINE_UNAVAILABLE", 503)
            return {
                "event_id": event.id,
                "tool": event.tool,
                "risk": facts["tool"]["risk"],
                "current_effect": left.effect,
                "candidate_effect": right.effect,
                "current_reasons": left.reason_codes,
                "candidate_reasons": right.reason_codes,
                "regression": left.effect != right.effect
                and (
                    right.effect == "deny"
                    or (right.effect == "allow" and facts["tool"]["risk"] != "R0")
                ),
            }

        results.extend(await asyncio.gather(*(compare(event, facts) for event, facts in batch)))
    counts = Counter(
        item["candidate_effect"]
        for item in results
        if item["current_effect"] != item["candidate_effect"]
    )
    report = {"current": current.id, "candidate": candidate.id, "changes": counts, "cases": results}
    if body.save:
        async with rt.sessions.begin() as db:
            row = Simulation(tenant=p.tenant, report=report)
            db.add(row)
            await db.flush()
            await audit.append(
                db,
                p,
                request.state.trace,
                "policy",
                "allow",
                "SIMULATION_SAVED",
                "recorded",
                details={"simulation_id": row.id},
            )
            return report | {"id": row.id}
    return report


@router.get("/policies/simulations/{identifier}")
async def simulation_detail(request: Request, p: Auditor, identifier: str):
    async with runtime(request).sessions() as db:
        return (await scoped(db, Simulation, p.tenant, identifier)).report


@router.get("/approvals")
async def approvals(request: Request, p: Actor, status: str | None = None):
    async with runtime(request).sessions() as db:
        stmt = select(Approval).where(Approval.tenant == p.tenant)
        if "security_admin" not in p.roles:
            stmt = stmt.where(Approval.requester == p.sub)
        if status == "EXPIRED":
            stmt = stmt.where(
                or_(
                    Approval.status == "EXPIRED",
                    and_(Approval.status.in_(("PENDING", "APPROVED")), Approval.expires <= now()),
                )
            )
        elif status:
            stmt = stmt.where(Approval.status == status)
            if status in ("PENDING", "APPROVED"):
                stmt = stmt.where(Approval.expires > now())
        rows = (await db.scalars(stmt.order_by(Approval.created.desc()).limit(100))).all()
    return [approval_view(row) for row in rows]


@router.get("/approvals/{identifier}")
async def approval_detail(request: Request, p: Actor, identifier: str):
    async with runtime(request).sessions() as db:
        row = await scoped(db, Approval, p.tenant, identifier)
        if p.sub != row.requester and "security_admin" not in p.roles:
            raise APIError("NOT_FOUND", 404)
        reviews = (
            await db.scalars(
                select(ApprovalReview).where(
                    ApprovalReview.tenant == p.tenant, ApprovalReview.approval_id == row.id
                )
            )
        ).all()
    return approval_view(row) | {
        "reviews": [row_view(review, "reviewer action rationale created") for review in reviews]
    }


@router.get("/approvals/{identifier}/arguments")
async def reveal_arguments(request: Request, p: Operator, identifier: str):
    if "approvals:review" not in p.scopes:
        raise APIError("APPROVAL_SCOPE_REQUIRED", 403)
    rt = runtime(request)
    async with rt.sessions.begin() as db:
        row = await scoped(db, Approval, p.tenant, identifier)
        if row.requester == p.sub or row.expires <= now() or not row.encrypted_arguments:
            raise APIError("ACTION_DETAILS_UNAVAILABLE", 403)
        data = json.loads(review_cipher(rt.cfg).decrypt(row.encrypted_arguments.encode()))
        await audit.append(
            db,
            p,
            request.state.trace,
            row.tool,
            "allow",
            "APPROVAL_DETAILS_REVEALED",
            "recorded",
            details={"approval_id": row.id},
        )
    return data


@router.post("/approvals/{identifier}/{action}")
async def review(
    request: Request,
    p: Operator,
    identifier: str,
    action: Literal["approve", "reject", "revoke"],
    body: Rationale,
):
    if "approvals:review" not in p.scopes:
        raise APIError("APPROVAL_SCOPE_REQUIRED", 403)
    async with runtime(request).sessions.begin() as db:
        row = await scoped(db, Approval, p.tenant, identifier, lock=True)
        if row.requester == p.sub:
            raise APIError("SELF_APPROVAL_DENIED", 403)
        allowed = {"PENDING", "APPROVED"} if action == "revoke" else {"PENDING"}
        if row.status not in allowed or row.expires <= now():
            raise APIError("APPROVAL_NOT_REVIEWABLE", 409)
        row.status = {"approve": "APPROVED", "reject": "REJECTED", "revoke": "REVOKED"}[action]
        row.reviewer = p.sub
        db.add(
            ApprovalReview(
                tenant=p.tenant,
                approval_id=row.id,
                reviewer=p.sub,
                action=action,
                rationale=redact(body.rationale),
            )
        )
        await audit.append(
            db,
            p,
            request.state.trace,
            row.tool,
            "allow",
            "APPROVAL_" + row.status,
            "recorded",
            details={"approval_id": row.id},
        )
    return approval_view(row)


@router.post("/executions/{identifier}/reconcile")
async def reconcile(request: Request, p: Operator, identifier: str, body: Rationale):
    async with runtime(request).sessions.begin() as db:
        row = await scoped(db, Execution, p.tenant, identifier, lock=True)
        if row.state != "UNKNOWN_REQUIRES_RECONCILIATION" and not (
            row.state == "RESERVED" and now() - row.created > 30
        ):
            raise APIError("EXECUTION_NOT_RECONCILABLE", 409)
        upstream = await db.get(UpstreamOperation, identifier)
        if upstream is None:
            raise APIError("UPSTREAM_OUTCOME_UNCONFIRMED", 409)
        if (
            upstream.tenant != p.tenant
            or upstream.tool != row.tool
            or upstream.actor != row.principal
        ):
            raise APIError("UPSTREAM_RECEIPT_MISMATCH", 409)
        row.state = "FAILED_NO_EFFECT" if "code" in upstream.result else "SUCCEEDED"
        if row.approval_id:
            await db.execute(
                update(Approval)
                .where(Approval.tenant == p.tenant, Approval.id == row.approval_id)
                .values(status="CONSUMED" if row.state == "SUCCEEDED" else row.state)
            )
        await audit.append(
            db,
            p,
            request.state.trace,
            row.tool,
            "allow",
            "EXECUTION_RECONCILED",
            "recorded",
            details={"execution_id": identifier, "reason": redact(body.rationale)},
        )
    return row_view(row, "id state trace")


@router.get("/audit/events")
async def events(
    request: Request,
    p: Auditor,
    cursor: int | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    tool: str | None = None,
    effect: str | None = None,
    reason: str | None = None,
    trace: str | None = None,
    subject: str | None = None,
    since: int | None = None,
    export: bool = False,
):
    stmt = select(Audit).where(Audit.tenant == p.tenant)
    for field, value in (
        (Audit.tool, tool),
        (Audit.effect, effect),
        (Audit.reason, reason),
        (Audit.trace, trace),
        (Audit.principal, subject),
    ):
        if value:
            stmt = stmt.where(field == value)
    if cursor is not None:
        stmt = stmt.where(Audit.seq < cursor)
    if since is not None:
        stmt = stmt.where(Audit.occurred >= since)
    async with runtime(request).sessions() as db:
        rows = (await db.scalars(stmt.order_by(Audit.seq.desc()).limit(limit + 1))).all()
    data = {
        "items": [audit.view(row) for row in rows[:limit]],
        "next_cursor": rows[limit - 1].seq if len(rows) > limit else None,
    }
    if export:
        return JSONResponse(
            data, headers={"Content-Disposition": 'attachment; filename="security-events.json"'}
        )
    return data


@router.get("/audit/events/{identifier}")
async def event_detail(request: Request, p: Auditor, identifier: str):
    async with runtime(request).sessions() as db:
        row = await scoped(db, Audit, p.tenant, identifier)
    return audit.view(row) | {"hash": row.hash}


@router.get("/audit/integrity")
async def verify_audit(request: Request, p: Auditor):
    async with runtime(request).sessions.begin() as db:
        return await audit.integrity(db, p.tenant)


@router.get("/benchmarks/runs")
async def runs(request: Request, p: Auditor):
    async with runtime(request).sessions() as db:
        rows = (
            await db.scalars(
                select(BenchmarkRun)
                .where(BenchmarkRun.tenant == p.tenant)
                .order_by(BenchmarkRun.created.desc())
                .limit(25)
            )
        ).all()
    return [row_view(row, "id created summary") for row in rows]


@router.post("/benchmarks/runs", status_code=201)
async def run_benchmark(request: Request, p: Operator, body: LabInput):
    from .lab import run_lab

    rt = runtime(request)
    if rt.lab_lock.locked():
        raise APIError("BENCHMARK_BUSY", 409)
    async with rt.lab_lock:
        try:
            summary, results = await run_lab(rt.cfg, body.scenario)
        except ValueError as error:
            raise APIError("UNKNOWN_SCENARIO", 404) from error
        async with rt.sessions.begin() as db:
            row = BenchmarkRun(tenant=p.tenant, summary=summary)
            db.add(row)
            await db.flush()
            for ordinal, item in enumerate(results):
                db.add(BenchmarkResult(run_id=row.id, ordinal=ordinal, result=item))
            await audit.append(
                db,
                p,
                request.state.trace,
                "benchmark",
                "allow",
                "BENCHMARK_COMPLETED",
                "recorded",
                details={"run_id": row.id, "scenario": body.scenario},
            )
    return {"id": row.id, "summary": summary}


@router.get("/benchmarks/runs/{identifier}")
async def run_detail(request: Request, p: Auditor, identifier: str):
    async with runtime(request).sessions() as db:
        return row_view(await scoped(db, BenchmarkRun, p.tenant, identifier), "id created summary")


@router.get("/benchmarks/runs/{identifier}/results")
async def run_results(
    request: Request, p: Auditor, identifier: str, offset: Annotated[int, Query(ge=0)] = 0
):
    async with runtime(request).sessions() as db:
        await scoped(db, BenchmarkRun, p.tenant, identifier)
        rows = (
            await db.scalars(
                select(BenchmarkResult)
                .where(BenchmarkResult.run_id == identifier)
                .order_by(BenchmarkResult.ordinal)
                .offset(offset)
                .limit(100)
            )
        ).all()
    return [row.result for row in rows]


@router.get("/settings")
async def settings(request: Request, p: Actor):
    rt = runtime(request)
    async with rt.sessions() as db:
        row = await active_policy(db, p.tenant)
        memberships = []
        if "security_admin" in p.roles:
            members = (
                await db.execute(
                    select(Membership, PrincipalRecord.name)
                    .join(PrincipalRecord)
                    .where(Membership.tenant == p.tenant)
                )
            ).all()
            memberships = [
                {"sub": member.sub, "roles": member.roles, "enabled": member.enabled, "name": name}
                for member, name in members
            ]
    return {
        "tenant": p.tenant,
        "roles": sorted(p.roles),
        "policy": row.config,
        "approval_ttl": rt.cfg.approval_ttl,
        "review_retention_days": rt.cfg.review_retention_days,
        "quota_per_minute": rt.cfg.quota_per_minute,
        "memberships": memberships,
    }


@router.post("/settings/memberships/{subject}")
async def update_membership(request: Request, p: Operator, subject: str, body: MembershipInput):
    if subject == p.sub or set(body.roles) - ROLES:
        raise APIError("MEMBERSHIP_CHANGE_FORBIDDEN", 403)
    # Admin grants require deployment-side provisioning. Existing administrators
    # can manage ordinary operator roles and revoke access immediately.
    async with runtime(request).sessions.begin() as db:
        member = await db.scalar(
            select(Membership)
            .where(Membership.sub == subject, Membership.tenant == p.tenant)
            .with_for_update()
        )
        if member is None:
            raise APIError("NOT_FOUND", 404)
        if "security_admin" in member.roles or "security_admin" in body.roles:
            raise APIError("ADMIN_MEMBERSHIP_REQUIRES_PROVISIONING", 403)
        member.roles = sorted(set(body.roles))
        member.enabled = body.enabled
        await audit.append(
            db,
            p,
            request.state.trace,
            "membership",
            "allow",
            "MEMBERSHIP_UPDATED",
            "recorded",
            details={
                "subject": subject,
                "roles": member.roles,
                "enabled": member.enabled,
                "reason": redact(body.rationale),
            },
        )
    return {"sub": subject, "enabled": member.enabled, "roles": member.roles}
