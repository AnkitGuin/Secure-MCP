import os
from contextlib import asynccontextmanager
from typing import Any

import jwt
from fastapi import FastAPI, Request
from jsonschema import Draft202012Validator
from mcp import types
from mcp.server.lowlevel import Server
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from starlette.responses import JSONResponse

from .config import CONNECTORS, ConnectorSettings, Settings
from .db import (
    Customer,
    Document,
    Export,
    Message,
    Note,
    UpstreamOperation,
    database,
    now,
    uid,
)
from .security import address, digest, domain
from .tools import TOOLS
from .wire import manager_for, mount_mcp, request_state, result

ISSUER = "securemcp-connector"


def service_token(
    cfg: Settings | ConnectorSettings,
    connector: str,
    tenant: str,
    sub: str,
    actor: str,
    roles: list[str],
    scopes: list[str],
):
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": connector,
            "sub": sub,
            "tenant": tenant,
            "actor": actor,
            "roles": roles,
            "scopes": scopes,
            "iat": now(),
            "exp": now() + 20,
        },
        cfg.secret(connector),
        algorithm="HS256",
    )


def customer_json(row: Customer):
    return {
        "id": row.id,
        "name": row.name,
        "status": row.status,
        "classification": row.classification,
        "email": row.email,
        "ssn_demo": row.ssn_demo,
    }


def document_json(row: Document, *, body: bool = False):
    content = {
        "id": row.id,
        "title": row.title,
        "classification": row.classification,
        "provenance": "untrusted synthetic document",
    }
    return {**content, "body": row.body} if body else content


def scoped_rows(model, actor):
    stmt = select(model).where(model.tenant == actor["tenant"])
    if model is Customer:
        stmt = stmt.where(Customer.deleted.is_(False))
    if model in (Customer, Document):
        if not {"team_lead", "sandbox_baseline"}.intersection(actor["roles"]):
            owner = (
                f"{actor['tenant']}-support" if "demo_agent" in actor["roles"] else actor["actor"]
            )
            stmt = stmt.where(model.owner == owner)
        if "restricted:read" not in actor["scopes"]:
            stmt = stmt.where(model.classification != "restricted")
    return stmt


async def operate(db, name: str, args: dict, actor: dict) -> dict[str, Any] | None:
    tenant = actor["tenant"]
    if name == "list_customers":
        rows = (
            await db.scalars(
                scoped_rows(Customer, actor)
                .order_by(Customer.id)
                .offset(args.get("offset", 0))
                .limit(args.get("limit", 10))
            )
        ).all()
        return {"customers": [customer_json(row) for row in rows]}
    if name in {
        "get_customer",
        "update_customer_note",
        "update_customer_status",
        "delete_customer",
    }:
        stmt = scoped_rows(Customer, actor).where(Customer.id == args["customer_id"])
        if name != "get_customer":
            stmt = stmt.with_for_update()
        row = await db.scalar(stmt)
        if row is None:
            return None
        if name == "get_customer":
            return {"customer": customer_json(row)}
        if name == "update_customer_note":
            item = Note(id=uid(), tenant=tenant, customer=row.id, body=args["note"])
            db.add(item)
            return {"note_id": item.id}
        if name == "delete_customer":
            row.deleted = True
            return {"customer_id": row.id, "deleted": True}
        row.status = args["status"]
        return {"customer_id": row.id, "status": row.status}
    if name == "export_customers":
        rows = (
            await db.scalars(
                scoped_rows(Customer, actor).order_by(Customer.id).limit(args["limit"])
            )
        ).all()
        destination = domain(args["destination"])
        item = Export(
            id=uid(),
            tenant=tenant,
            destination=destination,
            records=[customer_json(row) for row in rows],
        )
        db.add(item)
        return {"artifact_id": item.id, "records": len(item.records), "destination": destination}
    if name == "search_documents":
        stmt = scoped_rows(Document, actor).where(
            Document.title.icontains(args["query"], autoescape=True)
        )
        rows = (await db.scalars(stmt.order_by(Document.id).limit(args.get("limit", 10)))).all()
        return {"documents": [document_json(row) for row in rows]}
    if name == "read_document":
        row = await db.scalar(
            scoped_rows(Document, actor).where(Document.id == args["document_id"])
        )
        return {"document": document_json(row, body=True)} if row else None
    if name == "list_messages":
        rows = (
            await db.scalars(
                scoped_rows(Message, actor).order_by(Message.id).limit(args.get("limit", 10))
            )
        ).all()
        return {
            "messages": [
                {
                    "id": row.id,
                    "recipient": row.recipient,
                    "subject": row.subject,
                    "body": row.body,
                    "state": row.state,
                }
                for row in rows
            ]
        }
    if name == "send_message":
        recipient, target = address(args["to"])
        item = Message(
            id=uid(),
            tenant=tenant,
            recipient=recipient,
            domain=target,
            subject=args["subject"],
            body=args["body"],
        )
        db.add(item)
        return {"message_id": item.id, "state": "synthetic_outbox", "domain": target}
    return None


def create_upstream(
    cfg: Settings | ConnectorSettings,
    connector: str,
    sessions,
    *,
    close=None,
    catalog_override=None,
    after_commit=None,
    sandbox_baseline=False,
):
    specs = {spec.name: spec for spec in TOOLS.values() if spec.connector == connector}

    async def list_tools(context, _params):
        request_state(context).actor
        catalog = [spec.wire() for spec in sorted(specs.values(), key=lambda item: item.name)]
        if catalog_override is not None:
            catalog = catalog_override(catalog)
        return types.ListToolsResult(tools=catalog, ttl_ms=0)

    async def call_tool(context, params):
        actor = request_state(context).actor
        spec = specs.get(params.name)
        args = params.arguments or {}
        if spec is None or not Draft202012Validator(spec.wire().input_schema).is_valid(args):
            return result({"code": "UPSTREAM_INVALID_ARGUMENTS"}, error=True)
        if spec.scope not in actor["scopes"] and "sandbox_baseline" not in actor["roles"]:
            return result({"code": "UPSTREAM_NOT_AUTHORIZED"}, error=True)
        operation_id = args.get("operation_id")
        fingerprint = digest(args)
        try:
            async with sessions.begin() as db:
                if spec.write:
                    entry = UpstreamOperation(
                        id=operation_id,
                        tenant=actor["tenant"],
                        actor=actor["sub"],
                        tool=spec.id,
                        digest=fingerprint,
                        result={},
                    )
                    db.add(entry)
                    await db.flush()
                payload = await operate(db, spec.name, args, actor)
                if spec.write:
                    entry.result = payload or {"code": "UPSTREAM_RESOURCE_NOT_ACCESSIBLE"}
        except IntegrityError:
            async with sessions() as db:
                entry = await db.get(UpstreamOperation, operation_id)
                if (
                    entry is None
                    or entry.tenant != actor["tenant"]
                    or entry.actor != actor["sub"]
                    or entry.tool != spec.id
                    or entry.digest != fingerprint
                ):
                    return result({"code": "UPSTREAM_OPERATION_CONFLICT"}, error=True)
                payload = entry.result
        except (ValueError, TypeError):
            return result({"code": "UPSTREAM_INVALID_ARGUMENTS"}, error=True)
        if spec.write and after_commit:
            await after_commit(spec, args)
        if payload is None or "code" in payload:
            return result({"code": "UPSTREAM_RESOURCE_NOT_ACCESSIBLE"}, error=True)
        return result(payload)

    server = Server(
        f"securemcp-{connector}", version="1.0.0", on_list_tools=list_tools, on_call_tool=call_tool
    )
    manager = manager_for(server, cfg.max_request)

    @asynccontextmanager
    async def lifespan(_app):
        try:
            async with manager.run():
                yield
        finally:
            if close:
                await close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        if request.url.path.rstrip("/") == "/mcp":
            auth = request.headers.get("authorization", "")
            try:
                if not auth.startswith("Bearer ") or len(auth) > 4096:
                    raise ValueError
                claims = jwt.decode(
                    auth[7:],
                    cfg.secret(connector),
                    algorithms=["HS256"],
                    issuer=ISSUER,
                    audience=connector,
                    options={"require": ["exp", "iat", "tenant", "actor", "sub"]},
                )
                if claims.get("tenant") not in {"aurora", "borealis"} or (
                    "sandbox_baseline" in claims.get("roles", []) and not sandbox_baseline
                ):
                    raise ValueError
                request.state.actor = claims
            except (ValueError, jwt.PyJWTError):
                return JSONResponse({"error": "UNAUTHORIZED"}, status_code=401)
        return await call_next(request)

    @app.get("/health/live")
    async def live():
        return {"status": "ok"}

    mount_mcp(app, manager)
    return app


def app_factory():
    connector = os.environ["SMCP_CONNECTOR"]
    cfg = ConnectorSettings() if os.environ.get("SMCP_CONNECTOR_SECRET") else Settings()
    if connector not in CONNECTORS:
        raise ValueError("Unknown connector")
    engine, sessions = database(cfg.database_url)
    return create_upstream(cfg, connector, sessions, close=engine.dispose)
