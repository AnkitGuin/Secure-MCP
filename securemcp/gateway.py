import asyncio
from contextlib import asynccontextmanager
from uuid import UUID

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from mcp import types
from mcp.server.lowlevel import Server
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from redis.asyncio import Redis
from sqlalchemy import text
from starlette.responses import JSONResponse, Response

from .admin import APIError, router
from .config import CONNECTORS, Settings
from .db import database, uid
from .execution import ExecutionService
from .policy import OPA, Quota
from .registry import Registry
from .retention import worker
from .security import OIDC, AuthError
from .wire import APPROVAL_META, GATEWAY_NAME, manager_for, mount_mcp, request_state, result

AUTH_FAILURES = Counter(
    "securemcp_auth_rejections_total", "Authentication failures by reason", ["code"]
)


class Runtime:
    def __init__(
        self, cfg: Settings, *, identity_transport=None, upstream_transport=None, quota=None
    ):
        self.cfg = cfg
        self.engine, self.sessions = database(
            cfg.database_url, sandbox=cfg.database_url.startswith("sqlite")
        )
        self.http = httpx.AsyncClient(
            timeout=httpx.Timeout(2.5),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
            transport=identity_transport,
        )
        self.redis = Redis.from_url(
            cfg.redis_url, socket_timeout=1.0, socket_connect_timeout=1.0, max_connections=32
        )
        self.oidc = OIDC(cfg, self.sessions, self.http)
        self.opa = OPA(cfg.opa_url, self.http)
        self.registry = Registry(cfg, self.sessions, upstream_transport)
        self.execution = ExecutionService(
            cfg,
            self.sessions,
            self.registry,
            self.opa,
            quota or Quota(self.redis, cfg.quota_per_minute),
        )
        self.lab_lock = asyncio.Lock()

    async def close(self):
        await self.http.aclose()
        await self.redis.aclose()
        await self.engine.dispose()

    async def health(self):
        async def check(task):
            try:
                await task
                return True
            except (OSError, RuntimeError, httpx.HTTPError, TimeoutError):
                return False
            except Exception:
                return False

        async def http(url):
            (await self.http.get(url)).raise_for_status()

        async def db():
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))

        values = await asyncio.gather(
            check(db()),
            check(self.redis.ping()),
            check(http(self.cfg.opa_url + "/health")),
            check(http(self.oidc.backchannel + "/.well-known/openid-configuration")),
        )
        return {
            "gateway": True,
            **dict(zip(("database", "rate_control", "policy", "identity"), values, strict=True)),
        }


def error_response(request: Request, code: str, status: int, headers=None):
    return JSONResponse(
        {
            "error": {
                "code": code,
                "message": code.replace("_", " ").title(),
                "request_id": request.state.trace,
            }
        },
        status_code=status,
        headers={
            "X-Request-ID": request.state.trace,
            "Cache-Control": "no-store",
            **(headers or {}),
        },
    )


def create_app(rt: Runtime):
    cfg = rt.cfg

    async def list_tools(context, params):
        state = request_state(context)
        if params and params.cursor:
            return types.ListToolsResult(tools=[], ttl_ms=0)
        return types.ListToolsResult(
            tools=await rt.execution.catalog(state.principal, state.trace), ttl_ms=0
        )

    async def call_tool(context, params):
        state = request_state(context)
        approval = (context.meta or {}).get(APPROVAL_META)
        if approval is not None:
            try:
                if not isinstance(approval, str) or str(UUID(approval)) != approval:
                    raise ValueError
            except ValueError:
                return result({"code": "APPROVAL_INVALID", "request_id": state.trace}, error=True)
        return await rt.execution.execute(
            state.principal, state.trace, params.name, params.arguments or {}, approval
        )

    server = Server(GATEWAY_NAME, version="0.1.0", on_list_tools=list_tools, on_call_tool=call_tool)
    manager = manager_for(server, cfg.max_request)

    @asynccontextmanager
    async def lifespan(_app):
        cleanup = asyncio.create_task(worker(rt.sessions, cfg.review_retention_days * 86400))
        try:
            async with manager.run():
                yield
        finally:
            cleanup.cancel()
            await asyncio.gather(cleanup, return_exceptions=True)
            await rt.close()

    app = FastAPI(
        lifespan=lifespan, docs_url=None, openapi_url=None, redoc_url=None, redirect_slashes=False
    )
    app.state.runtime = rt

    @app.exception_handler(APIError)
    async def api_error(request: Request, error: APIError):
        return error_response(request, error.code, error.status)

    @app.exception_handler(RequestValidationError)
    async def request_error(request: Request, _error: RequestValidationError):
        return error_response(request, "INVALID_REQUEST", 422)

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        request.state.trace = uid()
        path = request.url.path
        is_mcp = path == "/mcp"
        is_control = path.startswith("/api/v1/") or path == "/metrics"
        origin = request.headers.get("origin")
        if (is_mcp or is_control) and origin and origin != cfg.browser_origin:
            return error_response(request, "ORIGIN_FORBIDDEN", 403)
        if is_mcp or is_control:
            try:
                request.state.principal = await rt.oidc.verify(request.headers.get("authorization"))
                if is_mcp and "mcp:tools" not in request.state.principal.scopes:
                    raise AuthError("INSUFFICIENT_SCOPE", 403)
            except AuthError as error:
                AUTH_FAILURES.labels(error.code).inc()
                metadata = (
                    cfg.resource_url.rsplit("/mcp", 1)[0]
                    + "/.well-known/oauth-protected-resource/mcp"
                )
                problem = "insufficient_scope" if error.status == 403 else "invalid_token"
                if error.code == "TOKEN_REQUIRED":
                    challenge = f'Bearer resource_metadata="{metadata}", scope="mcp:tools"'
                else:
                    challenge = f'Bearer error="{problem}", resource_metadata="{metadata}"'
                return error_response(
                    request,
                    error.code,
                    error.status,
                    {"WWW-Authenticate": challenge, "Cache-Control": "no-store"},
                )
            except Exception:
                return error_response(request, "IDENTITY_UNAVAILABLE", 503)
        if is_control and request.method in {"POST", "PATCH", "PUT"}:
            if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
                return error_response(request, "CONTENT_TYPE_REQUIRED", 415)
            buffered = bytearray()
            async for chunk in request.stream():
                if len(buffered) + len(chunk) > cfg.max_request:
                    return error_response(request, "PAYLOAD_TOO_LARGE", 413)
                buffered.extend(chunk)
            # Re-expose the bounded body to Starlette's downstream request.
            request._body = bytes(buffered)
        try:
            response = await call_next(request)
        except Exception:
            return error_response(request, "SERVICE_UNAVAILABLE", 503)
        response.headers["X-Request-ID"] = request.state.trace
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health/live")
    async def live():
        return {"status": "ok"}

    @app.get("/health/ready")
    async def ready():
        async def connector_health(name: str) -> bool:
            try:
                base = cfg.endpoint(name).removesuffix("/mcp")
                return (await rt.http.get(base + "/health/live")).is_success
            except httpx.HTTPError:
                return False

        services, connectors = await asyncio.gather(
            rt.health(), asyncio.gather(*(connector_health(name) for name in CONNECTORS))
        )
        healthy = all(services.values()) and all(connectors)
        return JSONResponse(
            {"status": "ready" if healthy else "unavailable"}, status_code=200 if healthy else 503
        )

    @app.get("/.well-known/oauth-protected-resource")
    @app.get("/.well-known/oauth-protected-resource/mcp")
    async def protected_resource():
        return {
            "resource": cfg.resource_url,
            "authorization_servers": [cfg.oidc_issuer],
            "scopes_supported": ["mcp:tools"],
            "bearer_methods_supported": ["header"],
        }

    @app.get("/api/config")
    async def browser_config():
        return {
            "issuer": cfg.oidc_issuer,
            "client_id": cfg.public_client,
            "local_demo": cfg.local_demo,
        }

    @app.get("/api/v1/openapi.json")
    async def openapi(request: Request):
        if "security_admin" not in request.state.principal.roles:
            raise APIError("FORBIDDEN", 403)
        return app.openapi()

    @app.get("/metrics")
    async def metrics(request: Request):
        if not request.state.principal.roles.intersection({"security_admin", "auditor"}):
            raise APIError("FORBIDDEN", 403)
        return Response(generate_latest(), headers={"Content-Type": CONTENT_TYPE_LATEST})

    app.include_router(router)
    mount_mcp(app, manager)
    return app


def app_factory():
    import os

    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    provider = TracerProvider()
    if os.getenv("SMCP_TRACE_STDOUT") == "1":
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    return create_app(Runtime(Settings()))
