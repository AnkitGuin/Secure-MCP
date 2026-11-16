import asyncio
import logging

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from . import audit
from .db import Approval, now, uid
from .security import Principal

LOGGER = logging.getLogger(__name__)


async def sweep(sessions, retention_seconds: int):
    cutoff = now()
    async with sessions() as db:
        pending = (
            await db.execute(
                select(Approval.id, Approval.tenant)
                .where(Approval.status.in_(("PENDING", "APPROVED")), Approval.expires <= cutoff)
                .order_by(Approval.expires)
                .limit(100)
            )
        ).all()
    for identifier, tenant in pending:
        async with sessions.begin() as db:
            changed = await db.execute(
                update(Approval)
                .where(
                    Approval.id == identifier,
                    Approval.tenant == tenant,
                    Approval.status.in_(("PENDING", "APPROVED")),
                    Approval.expires <= cutoff,
                )
                .values(status="EXPIRED")
            )
            if changed.rowcount:
                system = Principal(
                    "system-retention", "system-retention", tenant, frozenset(), frozenset(), ""
                )
                await audit.append(
                    db,
                    system,
                    uid(),
                    "approval",
                    "allow",
                    "APPROVAL_EXPIRED",
                    "recorded",
                    details={"approval_id": identifier},
                )
    async with sessions.begin() as db:
        scrub = (
            select(Approval.id)
            .where(
                Approval.expires <= cutoff - retention_seconds,
                Approval.encrypted_arguments.is_not(None),
            )
            .order_by(Approval.expires)
            .limit(100)
        )
        await db.execute(
            update(Approval).where(Approval.id.in_(scrub)).values(encrypted_arguments=None)
        )


async def worker(sessions, retention_seconds: int):
    while True:
        await asyncio.sleep(45)
        try:
            await sweep(sessions, retention_seconds)
        except SQLAlchemyError as error:
            LOGGER.warning("Approval cleanup unavailable (%s)", type(error).__name__)
