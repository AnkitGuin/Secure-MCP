from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import NullPool


def uid() -> str:
    return str(uuid4())


def now() -> int:
    return int(datetime.now(UTC).timestamp())


class Base(DeclarativeBase):
    type_annotation_map = {dict: JSON, list: JSON}


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    enabled: Mapped[bool] = mapped_column(default=True)


class PrincipalRecord(Base):
    __tablename__ = "principals"
    sub: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    enabled: Mapped[bool] = mapped_column(default=True)


class Membership(Base):
    __tablename__ = "memberships"
    sub: Mapped[str] = mapped_column(ForeignKey("principals.sub"), primary_key=True)
    tenant: Mapped[str] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    roles: Mapped[list]
    enabled: Mapped[bool] = mapped_column(default=True)


class Scoped:
    tenant: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)


class Connector(Scoped, Base):
    __tablename__ = "connectors"
    tenant: Mapped[str] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    last_discovery: Mapped[int | None]


class Manifest(Scoped, Base):
    __tablename__ = "tool_manifests"
    tenant: Mapped[str] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    tool: Mapped[str] = mapped_column(String(96), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    connector: Mapped[str] = mapped_column(String(32))
    definition: Mapped[dict]
    fingerprint: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(20), default="APPROVED")
    created: Mapped[int] = mapped_column(default=now)


class PolicyVersion(Scoped, Base):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("tenant", "checksum", "id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    config: Mapped[dict]
    checksum: Mapped[str] = mapped_column(String(64))
    author: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(300))
    state: Mapped[str] = mapped_column(String(20))
    created: Mapped[int] = mapped_column(default=now)
    activated: Mapped[int | None]
    validated: Mapped[bool] = mapped_column(default=False)


class PolicyGrant(Scoped, Base):
    __tablename__ = "policy_grants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policy_versions.id"), index=True)
    role: Mapped[str] = mapped_column(String(32))
    tool: Mapped[str] = mapped_column(String(96))


class TenantState(Base):
    __tablename__ = "tenant_state"
    tenant: Mapped[str] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    active_policy: Mapped[str] = mapped_column(ForeignKey("policy_versions.id"))
    audit_seq: Mapped[int] = mapped_column(default=0)
    audit_head: Mapped[str] = mapped_column(String(64), default="0" * 64)


class Approval(Scoped, Base):
    __tablename__ = "approval_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    requester: Mapped[str] = mapped_column(ForeignKey("principals.sub"))
    tool: Mapped[str] = mapped_column(String(96))
    binding: Mapped[str] = mapped_column(String(64))
    preview: Mapped[dict]
    encrypted_arguments: Mapped[str | None] = mapped_column(Text)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policy_versions.id"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(40), default="PENDING")
    created: Mapped[int] = mapped_column(default=now)
    expires: Mapped[int] = mapped_column(index=True)
    reviewer: Mapped[str | None] = mapped_column(ForeignKey("principals.sub"))


class ApprovalReview(Scoped, Base):
    __tablename__ = "approval_reviews"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    approval_id: Mapped[str] = mapped_column(ForeignKey("approval_requests.id"), index=True)
    reviewer: Mapped[str] = mapped_column(ForeignKey("principals.sub"))
    action: Mapped[str] = mapped_column(String(20))
    rationale: Mapped[str] = mapped_column(String(300))
    created: Mapped[int] = mapped_column(default=now)


class Execution(Scoped, Base):
    __tablename__ = "execution_records"
    __table_args__ = (UniqueConstraint("tenant", "principal", "tool", "key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    principal: Mapped[str] = mapped_column(ForeignKey("principals.sub"))
    tool: Mapped[str] = mapped_column(String(96))
    key: Mapped[str] = mapped_column(String(100))
    digest: Mapped[str] = mapped_column(String(64))
    trace: Mapped[str] = mapped_column(String(36))
    approval_id: Mapped[str | None] = mapped_column(ForeignKey("approval_requests.id"), unique=True)
    state: Mapped[str] = mapped_column(String(40))
    created: Mapped[int] = mapped_column(default=now)


class Audit(Scoped, Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("tenant", "seq"),
        Index("ix_audit_tenant_time", "tenant", "occurred"),
        Index("ix_audit_tool_time", "tool", "occurred"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    seq: Mapped[int]
    trace: Mapped[str] = mapped_column(String(36), index=True)
    principal: Mapped[str] = mapped_column(String(128))
    tool: Mapped[str] = mapped_column(String(96))
    effect: Mapped[str] = mapped_column(String(24))
    reason: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(40))
    duration_ms: Mapped[int]
    occurred: Mapped[int]
    details: Mapped[dict]
    previous: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class Simulation(Scoped, Base):
    __tablename__ = "policy_simulations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    report: Mapped[dict]
    created: Mapped[int] = mapped_column(default=now)


class BenchmarkScenario(Base):
    __tablename__ = "benchmark_scenarios"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    definition: Mapped[dict]


class BenchmarkRun(Scoped, Base):
    __tablename__ = "benchmark_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    summary: Mapped[dict]
    created: Mapped[int] = mapped_column(default=now)


class BenchmarkResult(Base):
    __tablename__ = "benchmark_results"
    run_id: Mapped[str] = mapped_column(ForeignKey("benchmark_runs.id"), primary_key=True)
    ordinal: Mapped[int] = mapped_column(primary_key=True)
    result: Mapped[dict]


class Customer(Scoped, Base):
    __tablename__ = "customers"
    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    owner: Mapped[str] = mapped_column(String(80), index=True)
    name: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20), default="open")
    classification: Mapped[str] = mapped_column(String(20), default="internal")
    email: Mapped[str] = mapped_column(String(120))
    ssn_demo: Mapped[str] = mapped_column(String(32))
    deleted: Mapped[bool] = mapped_column(default=False)


class Document(Scoped, Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    title: Mapped[str] = mapped_column(String(100))
    body: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(80))
    classification: Mapped[str] = mapped_column(String(20))


class Note(Scoped, Base):
    __tablename__ = "notes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    customer: Mapped[str] = mapped_column(ForeignKey("customers.id"))
    body: Mapped[str] = mapped_column(Text)


class Message(Scoped, Base):
    __tablename__ = "messages"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    recipient: Mapped[str] = mapped_column(String(254))
    domain: Mapped[str] = mapped_column(String(253))
    subject: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(30), default="synthetic_outbox")


class Export(Scoped, Base):
    __tablename__ = "exports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    destination: Mapped[str] = mapped_column(String(253))
    records: Mapped[list]


class UpstreamOperation(Scoped, Base):
    __tablename__ = "upstream_operations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tool: Mapped[str] = mapped_column(String(96))
    actor: Mapped[str] = mapped_column(String(128))
    digest: Mapped[str] = mapped_column(String(64))
    result: Mapped[dict]


def database(url: str, *, sandbox: bool = False):
    options = {"poolclass": NullPool} if sandbox else {"pool_pre_ping": True}
    if url.startswith("postgresql") and not sandbox:
        options.update({"pool_size": 10, "max_overflow": 10, "pool_timeout": 5})
    engine = create_async_engine(url, **options)
    return engine, async_sessionmaker(engine, expire_on_commit=False)
