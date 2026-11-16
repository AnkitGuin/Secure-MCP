"""Independent MCP SDK smoke and demo client for the local stack."""

import argparse
import asyncio
import json
import os
from uuid import uuid4

import httpx

from securemcp.wire import APPROVAL_META, mcp_client

GATEWAY = os.getenv("SMCP_GATEWAY_HTTP", "http://localhost:5173")
ISSUER = os.getenv("SMCP_OIDC_ISSUER", "http://localhost:8080/realms/securemcp")


async def token(username: str):
    form = (
        {
            "grant_type": "client_credentials",
            "client_id": "securemcp-agent",
            "client_secret": os.environ["DEMO_AGENT_SECRET"],
        }
        if username == "aurora-agent"
        else {
            "grant_type": "password",
            "client_id": "securemcp-cli",
            "username": username,
            "password": os.environ["DEMO_PASSWORD"],
        }
    )
    async with httpx.AsyncClient(trust_env=False, timeout=10) as client:
        response = await client.post(ISSUER + "/protocol/openid-connect/token", data=form)
        response.raise_for_status()
    return response.json()["access_token"]


async def smoke():
    bearer = await token("aurora-support")
    for mode in ("auto", "legacy"):
        async with mcp_client(GATEWAY + "/mcp", bearer, mode=mode) as client:
            catalog = await client.list_tools()
            assert "crm__get_customer" in {tool.name for tool in catalog.tools}, catalog
            assert "crm__export_customers" not in {tool.name for tool in catalog.tools}
            reply = await client.call_tool("crm__get_customer", {"customer_id": "cus-a-01"})
            assert not reply.is_error, reply.structured_content
            assert reply.structured_content["data"]["customer"]["email"] == "[redacted]"
            print(
                mode, client.protocol_version, len(catalog.tools), "tools; customer read succeeded"
            )
    agent = await token("aurora-agent")
    async with mcp_client(GATEWAY + "/mcp", agent) as client:
        assert "crm__update_customer_status" not in {
            tool.name for tool in (await client.list_tools()).tools
        }
        print("Keycloak client-credentials agent: read-only catalog")


async def demos():
    async with mcp_client(GATEWAY + "/mcp", await token("aurora-support")) as support:

        def args(customer):
            return {"customer_id": customer}

        for customer in ("cus-a-01", "cus-b-01"):
            reply = await support.call_tool("crm__get_customer", args(customer))
            assert reply.is_error == (customer == "cus-b-01")
            print("Customer read", customer, reply.structured_content)
        document = await support.call_tool("docs__read_document", {"document_id": "doc-a-02"})
        assert not document.is_error
        message = await support.call_tool(
            "messages__send_message",
            {
                "to": "attacker@external.example",
                "subject": "Synthetic",
                "body": "Injected request",
                "idempotency_key": str(uuid4()),
            },
        )
        assert message.is_error and message.structured_content["code"] == "DESTINATION_BLOCKED"
        print("Poison document external message", message.structured_content)
    reviewer = await token("aurora-security")
    headers = {"Authorization": "Bearer " + reviewer}
    async with (
        mcp_client(GATEWAY + "/mcp", await token("aurora-lead")) as lead,
        httpx.AsyncClient(trust_env=False, base_url=GATEWAY, headers=headers, timeout=90) as api,
    ):
        export = {"limit": 2, "destination": "aurora.example", "idempotency_key": str(uuid4())}
        blocked = await lead.call_tool(
            "crm__export_customers", {**export, "destination": "external.example"}
        )
        assert blocked.is_error and blocked.structured_content["code"] == "DESTINATION_BLOCKED"
        pending = await lead.call_tool("crm__export_customers", export)
        approval = pending.structured_content["approval_id"]
        print("Export awaiting review", approval)
        review = await api.post(
            f"/api/v1/approvals/{approval}/approve",
            json={"rationale": "Reviewed scoped local synthetic export."},
        )
        review.raise_for_status()
        approval_meta = {APPROVAL_META: approval}
        for changed, expected in (({**export, "limit": 3}, True), (export, False), (export, True)):
            reply = await lead.call_tool("crm__export_customers", changed, meta=approval_meta)
            assert reply.is_error == expected, reply.structured_content
            print("Export redemption", reply.structured_content)
        config = {"export_requires_approval": False, "external_domains": ["external.example"]}
        draft = await api.post(
            "/api/v1/policies/drafts",
            json={
                "config": config,
                "rationale": "Simulate a weakened export policy without activation.",
            },
        )
        draft.raise_for_status()
        comparison = await api.post(
            "/api/v1/policies/simulate",
            json={"candidate": draft.json()["id"], "tool": "crm__export_customers", "limit": 15},
        )
        comparison.raise_for_status()
        assert comparison.json()["changes"].get("allow", 0) >= 1, comparison.json()
        print("Policy comparison", comparison.json()["changes"])
        for scenario in ("INJECT-001", "INJECT-002", "TRUST-002"):
            run = await api.post("/api/v1/benchmarks/runs", json={"scenario": scenario})
            run.raise_for_status()
            values = run.json()["summary"]["modes"]["protected"]
            print("Isolated scenario", scenario, json.dumps(values))
            assert values["attack_success_rate"] == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("smoke", "demo"))
    args = parser.parse_args()
    asyncio.run(smoke() if args.command == "smoke" else demos())
