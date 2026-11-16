import asyncio
from collections.abc import Callable

from mcp import types
from sqlalchemy import select, update

from . import audit
from .config import Settings
from .db import Connector, Manifest, now
from .security import Principal, digest
from .upstream import service_token
from .wire import mcp_client

RemoteTransport = Callable[[str], object] | None


def snapshot(tool: types.Tool) -> dict:
    return tool.model_dump(by_alias=True, exclude_none=True, mode="json")


class RegistryError(Exception):
    pass


class Registry:
    def __init__(self, cfg: Settings, sessions, transport: RemoteTransport = None):
        self.cfg = cfg
        self.sessions = sessions
        self.transport = transport
        self.slots = asyncio.Semaphore(16)

    def client(self, connector: str, p: Principal):
        token = service_token(
            self.cfg, connector, p.tenant, p.sub, p.name, list(p.roles), list(p.scopes)
        )
        return mcp_client(
            self.cfg.endpoint(connector),
            token,
            timeout=self.cfg.call_timeout,
            max_response=self.cfg.max_response,
            transport=self.transport(connector) if self.transport else None,
        )

    async def remote_catalog(self, connector: str, p: Principal) -> dict[str, dict]:
        async with (
            asyncio.timeout(self.cfg.call_timeout),
            self.slots,
            self.client(connector, p) as client,
        ):
            if client.server_info is None or client.server_info.name != f"securemcp-{connector}":
                raise RegistryError("Connector identity mismatch")
            response = await client.list_tools(cache_mode="bypass")
            tools = {tool.name: snapshot(tool) for tool in response.tools}
            if response.next_cursor or len(tools) != len(response.tools) or len(tools) > 30:
                raise RegistryError("Unexpected connector catalog")
            return tools

    async def approved(self, tenant: str, tool: str):
        async with self.sessions() as db:
            return await db.scalar(
                select(Manifest)
                .join(
                    Connector,
                    (Connector.id == Manifest.connector) & (Connector.tenant == Manifest.tenant),
                )
                .where(
                    Manifest.tenant == tenant, Manifest.tool == tool, Connector.enabled.is_(True)
                )
                .order_by(Manifest.version.desc())
                .limit(1)
            )

    async def check(self, manifest: Manifest, catalog: dict[str, dict], p: Principal, trace: str):
        name = manifest.tool.split("__", 1)[1]
        fresh = catalog.get(name)
        if manifest.state != "APPROVED":
            return False
        if fresh and digest(fresh) == manifest.fingerprint:
            return True
        async with self.sessions.begin() as db:
            changed = await db.execute(
                update(Manifest)
                .where(
                    Manifest.tenant == p.tenant,
                    Manifest.tool == manifest.tool,
                    Manifest.version == manifest.version,
                    Manifest.state == "APPROVED",
                )
                .values(state="DRIFTED")
            )
            if changed.rowcount:
                await audit.append(
                    db,
                    p,
                    trace,
                    manifest.tool,
                    "deny",
                    "TOOL_SCHEMA_DRIFT",
                    "blocked",
                    details={"manifest": manifest.version, "fingerprint": manifest.fingerprint},
                )
        return False

    async def discover(self, connector: str, p: Principal, trace: str):
        catalog = await self.remote_catalog(connector, p)
        async with self.sessions.begin() as db:
            await db.execute(
                update(Connector)
                .where(Connector.tenant == p.tenant, Connector.id == connector)
                .values(last_discovery=now())
            )
        return catalog
