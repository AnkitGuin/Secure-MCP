from typing import Any

from sqlalchemy import select, update

from .db import Audit, TenantState, now, uid
from .security import Principal, digest

EVENT_FIELDS = (
    "id",
    "tenant",
    "seq",
    "trace",
    "principal",
    "tool",
    "effect",
    "reason",
    "outcome",
    "duration_ms",
    "occurred",
    "details",
    "previous",
)


def view(row: Audit) -> dict[str, Any]:
    return {key: getattr(row, key) for key in EVENT_FIELDS}


async def append(
    db,
    p: Principal,
    trace: str,
    tool: str,
    effect: str,
    reason: str,
    outcome: str,
    *,
    duration_ms=0,
    details=None,
):
    row = (
        await db.execute(
            update(TenantState)
            .where(TenantState.tenant == p.tenant)
            .values(audit_seq=TenantState.audit_seq + 1)
            .returning(TenantState.audit_seq, TenantState.audit_head)
        )
    ).one()
    event = dict(
        id=uid(),
        tenant=p.tenant,
        seq=row.audit_seq,
        trace=trace,
        principal=p.sub,
        tool=tool,
        effect=effect,
        reason=reason,
        outcome=outcome,
        duration_ms=duration_ms,
        occurred=now(),
        details=details or {},
        previous=row.audit_head,
    )
    checksum = digest(event)
    db.add(Audit(**event, hash=checksum))
    await db.execute(
        update(TenantState).where(TenantState.tenant == p.tenant).values(audit_head=checksum)
    )
    return event["id"]


async def integrity(db, tenant: str):
    state = await db.scalar(
        select(TenantState).where(TenantState.tenant == tenant).with_for_update()
    )
    if state is None:
        return {"valid": False, "events": 0}
    rows = await db.stream_scalars(select(Audit).where(Audit.tenant == tenant).order_by(Audit.seq))
    previous, count = "0" * 64, 0
    async for row in rows:
        count += 1
        if row.seq != count or row.previous != previous or digest(view(row)) != row.hash:
            return {"valid": False, "events": count}
        previous = row.hash
    return {"valid": state.audit_head == previous and state.audit_seq == count, "events": count}
