from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.requests import Request
from starlette.routing import Route

from .security import canonical

PROTOCOL = "2026-07-28"
APPROVAL_META = "securemcp.local/approval"
GATEWAY_NAME = "SecureMCP"


def result(data: dict[str, Any], *, error: bool = False) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=canonical(data).decode())],
        structured_content=data,
        is_error=error,
    )


def request_state(context):
    if not isinstance(context.request, Request):
        raise RuntimeError("HTTP context required")
    return context.request.state


def manager_for(server: Server, max_request: int) -> StreamableHTTPSessionManager:
    return StreamableHTTPSessionManager(
        server,
        json_response=True,
        stateless=True,
        max_request_body_size=max_request,
        max_sessions=32,
    )


class MCPEndpoint:
    def __init__(self, manager):
        self.manager = manager

    async def __call__(self, scope, receive, send):
        await self.manager.handle_request(scope, receive, send)


def mount_mcp(app, manager):
    app.router.routes.append(Route("/mcp", MCPEndpoint(manager)))


class WireLimit(Exception):
    pass


class BoundedStream(httpx2.AsyncByteStream):
    def __init__(self, wrapped, limit: int):
        self.wrapped = wrapped
        self.limit = limit

    async def __aiter__(self):
        size = 0
        async for chunk in self.wrapped:
            size += len(chunk)
            if size > self.limit:
                raise WireLimit("MCP response size exceeded")
            yield chunk

    async def aclose(self):
        await self.wrapped.aclose()


class BoundedTransport(httpx2.AsyncBaseTransport):
    def __init__(self, transport, endpoint: str, limit: int):
        self.transport = transport
        self.endpoint = httpx2.URL(endpoint)
        self.limit = limit

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if request.url != self.endpoint:
            raise WireLimit("Unapproved MCP endpoint")
        response = await self.transport.handle_async_request(request)
        if (
            300 <= response.status_code < 400
            or response.headers.get("content-encoding", "identity") != "identity"
        ):
            await response.aclose()
            raise WireLimit("Unapproved MCP response")
        response.stream = BoundedStream(response.stream, self.limit)
        return response

    async def aclose(self):
        await self.transport.aclose()


@asynccontextmanager
async def mcp_client(
    endpoint: str, bearer: str, *, mode="auto", timeout=5.0, max_response=65536, transport=None
) -> AsyncIterator[Client]:
    wire = BoundedTransport(
        transport
        or httpx2.AsyncHTTPTransport(
            retries=0, limits=httpx2.Limits(max_connections=8, max_keepalive_connections=4)
        ),
        endpoint,
        max_response,
    )
    async with httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {bearer}", "Accept-Encoding": "identity"},
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
        transport=wire,
    ) as http:
        async with Client(
            streamable_http_client(endpoint, http_client=http),
            read_timeout_seconds=timeout,
            mode=mode,
            cache=None,
            input_required_max_rounds=0,
        ) as client:
            yield client
