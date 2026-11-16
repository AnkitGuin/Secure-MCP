import asyncio
import os
from uuid import uuid4

import httpx
import httpx2
import jwt
import pytest
from hypothesis import given
from hypothesis import strategies as st
from jsonschema import Draft202012Validator
from redis.exceptions import RedisError
from sqlalchemy import select, update

from securemcp.config import Settings
from securemcp.db import Approval, Customer, Execution, Membership, now
from securemcp.demo_identities import IDENTITIES
from securemcp.lab import GATEWAY, REASON, cases, count_effects, exercise, sandbox
from securemcp.policy import OPA
from securemcp.security import address, digest, domain, has_sensitive
from securemcp.tools import TOOLS
from securemcp.wire import APPROVAL_META, mcp_client


@pytest.fixture
async def cfg():
    cfg = Settings(
        database_url="sqlite+aiosqlite:///unused.db",
        redis_url="redis://127.0.0.1:6379",
        local_demo=True,
        crm_secret="c" * 40,
        docs_secret="d" * 40,
        messages_secret="m" * 40,
        opa_url=os.getenv("SMCP_OPA_URL", "http://127.0.0.1:8181"),
    )
    async with httpx.AsyncClient(trust_env=False, timeout=1) as client:
        try:
            assert (await client.get(cfg.opa_url + "/health")).is_success
        except httpx.HTTPError:
            pytest.skip("Start OPA and set SMCP_OPA_URL to run policy integration tests")
    return cfg


@pytest.fixture
async def lab(cfg):
    ready = asyncio.get_running_loop().create_future()
    done = asyncio.Event()

    async def serve():
        async with sandbox(cfg) as state:
            ready.set_result(state)
            await done.wait()

    task = asyncio.create_task(serve())
    try:
        completed, _ = await asyncio.wait({task, ready}, return_when=asyncio.FIRST_COMPLETED)
        if task in completed:
            await task
        yield ready.result()
    finally:
        done.set()
        await task


def auth(issuer, name="aurora-security", variation=""):
    return {"Authorization": "Bearer " + issuer.token(name, variation)}


async def call(app, issuer, tool, args, name="aurora-support", approval=None, mode="2026-07-28"):
    async with mcp_client(
        GATEWAY, issuer.token(name), mode=mode, transport=httpx2.ASGITransport(app=app)
    ) as client:
        return await client.call_tool(
            tool, args, meta={APPROVAL_META: approval} if approval else None
        )


async def admin(app, issuer, path, body=None, name="aurora-security"):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://isolated-gateway",
        headers=auth(issuer, name),
    ) as client:
        return await (client.get(path) if body is None else client.post(path, json=body))


def export_args():
    return {"limit": 2, "destination": "aurora.example", "idempotency_key": str(uuid4())}


async def create_approval(app, issuer, args):
    response = await call(app, issuer, "crm__export_customers", args, name="aurora-lead")
    assert response.structured_content["code"] == "APPROVAL_REQUIRED", response.structured_content
    return response.structured_content["approval_id"]


@pytest.mark.parametrize("mode,version", [("auto", "2026-07-28"), ("legacy", "2025-11-25")])
async def test_sdk_protocol(lab, mode, version):
    rt, issuer, _, app, _ = lab
    async with mcp_client(
        GATEWAY, issuer.token("aurora-support"), mode=mode, transport=httpx2.ASGITransport(app=app)
    ) as client:
        assert client.protocol_version == version
        assert client.server_info.name == "SecureMCP"
        catalog = await client.list_tools()
        names = {tool.name for tool in catalog.tools}
        assert "crm__get_customer" in names and "crm__export_customers" not in names
        response = await client.call_tool("crm__get_customer", {"customer_id": "cus-a-01"})
        assert response.structured_content["data"]["customer"]["email"] == "[redacted]"
    async with rt.sessions() as db:
        assert (await db.get(Customer, "cus-a-01")).status == "open"


@pytest.mark.parametrize(
    "variation", ["missing", "bad_aud", "expired_token", "wrong_issuer", "forged", "none"]
)
async def test_invalid_access_token(lab, variation):
    _, issuer, _, app, _ = lab
    headers = auth(issuer, "aurora-support", variation)
    if variation == "missing":
        headers = {}
    if variation == "forged":
        old = headers["Authorization"]
        prefix, sig = old.rsplit(".", 1)
        headers["Authorization"] = prefix + "." + ("a" if sig[0] != "a" else "b") + sig[1:]
    if variation == "none":
        headers["Authorization"] = "Bearer " + jwt.encode({"sub": "x"}, None, algorithm="none")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://isolated-gateway"
    ) as client:
        response = await client.post("/mcp", headers=headers, json={})
        assert response.status_code == 401
        assert "resource_metadata=" in response.headers["www-authenticate"]


async def test_header_mismatch(lab):
    rt, issuer, _, app, _ = lab
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "crm__get_customer",
            "arguments": {"customer_id": "cus-a-01"},
            "_meta": {"io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"}},
        },
    }
    headers = auth(issuer, "aurora-support") | {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "docs__read_document",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://isolated-gateway"
    ) as client:
        response = await client.post("/mcp", headers=headers, json=body)
    assert response.status_code == 400 or "error" in response.json()
    assert (await count_effects(rt))["audit"] == 0


async def test_cross_tenant_customer_read(lab):
    _, issuer, _, app, _ = lab
    foreign = await call(app, issuer, "crm__get_customer", {"customer_id": "cus-b-01"})
    missing = await call(app, issuer, "crm__get_customer", {"customer_id": "unknown"})
    assert (
        foreign.structured_content["code"]
        == missing.structured_content["code"]
        == "RESOURCE_NOT_ACCESSIBLE"
    )


async def test_guessed_hidden_tool_and_scope(lab):
    _, issuer, _, app, _ = lab
    hidden = await call(app, issuer, "crm__export_customers", export_args())
    assert hidden.structured_content["code"] == "TOOL_NOT_AVAILABLE"
    denied = await call(
        app,
        issuer,
        "crm__update_customer_status",
        {"customer_id": "cus-a-01", "status": "resolved", "idempotency_key": str(uuid4())},
        name="aurora-agent",
    )
    assert denied.structured_content["code"] == "TOOL_NOT_AVAILABLE"


async def test_revoked_membership_and_browser_origin(lab):
    rt, issuer, _, app, _ = lab
    async with rt.sessions.begin() as db:
        await db.execute(
            update(Membership)
            .where(Membership.sub == IDENTITIES["aurora-support"][0])
            .values(enabled=False)
        )
    assert (await admin(app, issuer, "/api/v1/me", name="aurora-support")).status_code == 403
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://isolated-gateway"
    ) as client:
        response = await client.get(
            "/api/v1/me", headers=auth(issuer) | {"Origin": "https://evil.example"}
        )
        assert response.status_code == 403 and "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize("case_id,table", [("INJECT-001", "exports"), ("INJECT-002", "outbox")])
async def test_poison_has_no_effect(lab, case_id, table):
    case = next(case for case in cases() if case.id == case_id)
    protected = await exercise(case, "protected", *lab)
    assert not protected["unauthorized_effect"] and protected["db_delta"][table] == 0
    assert protected["codes"] == ["DESTINATION_BLOCKED"]
    baseline = await exercise(case, "direct", *lab)
    assert baseline["unauthorized_effect"] and baseline["db_delta"][table] == 1


async def test_legitimate_scoped_update_and_idempotency(lab):
    rt, issuer, _, app, _ = lab
    args = {"customer_id": "cus-a-01", "status": "resolved", "idempotency_key": str(uuid4())}
    before = await count_effects(rt)
    response = await call(app, issuer, "crm__update_customer_status", args)
    assert not response.is_error, response.structured_content
    replay = await call(app, issuer, "crm__update_customer_status", args | {"status": "pending"})
    assert replay.structured_content["code"] == "IDEMPOTENCY_CONFLICT"
    async with rt.sessions() as db:
        assert (await db.get(Customer, "cus-a-01")).status == "resolved"
    assert (await count_effects(rt))["operations"] - before["operations"] == 1


@pytest.mark.parametrize(
    "variant",
    ["pending", "expired", "revoked", "rejected", "changed", "wrong_requester", "reviewer_revoked"],
)
async def test_approval_invalid(lab, variant):
    rt, issuer, _, app, _ = lab
    args = export_args()
    approval = await create_approval(app, issuer, args)
    if variant != "pending":
        action = "reject" if variant == "rejected" else "approve"
        assert (
            await admin(app, issuer, f"/api/v1/approvals/{approval}/{action}", REASON)
        ).status_code == 200
    if variant == "expired":
        async with rt.sessions.begin() as db:
            await db.execute(
                update(Approval).where(Approval.id == approval).values(expires=now() - 1)
            )
    if variant == "revoked":
        assert (
            await admin(app, issuer, f"/api/v1/approvals/{approval}/revoke", REASON)
        ).status_code == 200
    if variant == "changed":
        args["limit"] += 1
    if variant == "reviewer_revoked":
        async with rt.sessions.begin() as db:
            await db.execute(
                update(Membership)
                .where(Membership.sub == IDENTITIES["aurora-security"][0])
                .values(enabled=False)
            )
    name = "borealis-support" if variant == "wrong_requester" else "aurora-lead"
    response = await call(app, issuer, "crm__export_customers", args, name=name, approval=approval)
    assert response.is_error and (await count_effects(rt))["exports"] == 0


async def test_self_approval(lab):
    rt, issuer, _, app, _ = lab
    approval = await create_approval(app, issuer, export_args())
    # Use an otherwise eligible reviewer to check the identity equality guard.
    row = await admin(app, issuer, f"/api/v1/approvals/{approval}", name="aurora-security")
    assert row.status_code == 200
    async with rt.sessions.begin() as db:
        await db.execute(
            update(Approval)
            .where(Approval.id == approval)
            .values(requester=IDENTITIES["aurora-security"][0])
        )
    denied = await admin(app, issuer, f"/api/v1/approvals/{approval}/approve", REASON)
    assert denied.json()["error"]["code"] == "SELF_APPROVAL_DENIED"


async def race(state, variant="parallel"):
    rt, issuer, faults, app, _ = state
    args = export_args()
    approval = await create_approval(app, issuer, args)
    assert (
        await admin(app, issuer, f"/api/v1/approvals/{approval}/approve", REASON)
    ).status_code == 200
    if variant == "timeout":
        faults["operation"] = "timeout"

    async def redeem():
        return await call(
            app, issuer, "crm__export_customers", args, name="aurora-lead", approval=approval
        )

    if variant == "parallel":
        responses = await asyncio.gather(redeem(), redeem())
        assert sum(not response.is_error for response in responses) == 1
    else:
        assert (await redeem()).structured_content["code"] == "UNKNOWN_REQUIRES_RECONCILIATION"
    assert (await redeem()).is_error
    assert (await count_effects(rt))["exports"] == 1
    async with rt.sessions() as db:
        records = (await db.scalars(select(Execution))).all()
        assert len(records) == 1
        assert records[0].state == (
            "SUCCEEDED" if variant == "parallel" else "UNKNOWN_REQUIRES_RECONCILIATION"
        )


async def test_concurrent_approval_redemption_postgres(cfg):
    url = os.getenv("SMCP_TEST_POSTGRES")
    if not url:
        pytest.skip("Set SMCP_TEST_POSTGRES to a dedicated empty PostgreSQL database")
    async with sandbox(cfg, url) as state:
        await race(state)


async def test_timeout_no_blind_retry(cfg):
    async with sandbox(cfg.model_copy(update={"call_timeout": 0.3})) as state:
        await race(state, "timeout")


async def test_opa_unavailable(lab):
    rt, issuer, _, app, _ = lab
    rt.opa.url = "http://127.0.0.1:9"
    denied = await call(
        app,
        issuer,
        "crm__update_customer_status",
        {"customer_id": "cus-a-01", "status": "resolved", "idempotency_key": str(uuid4())},
    )
    assert denied.structured_content["code"] == "POLICY_ENGINE_UNAVAILABLE"
    assert (await count_effects(rt))["operations"] == 0


@pytest.mark.parametrize("unavailable", [False, True])
async def test_rate_control_fails_closed(lab, unavailable):
    rt, issuer, _, app, _ = lab

    class RejectQuota:
        async def admit(self, _tenant, _sub):
            if unavailable:
                raise RedisError("unavailable")
            return False

    rt.execution.quota = RejectQuota()
    denied = await call(
        app,
        issuer,
        "crm__update_customer_status",
        {"customer_id": "cus-a-01", "status": "resolved", "idempotency_key": str(uuid4())},
    )
    assert denied.structured_content["code"] == (
        "RATE_CONTROL_UNAVAILABLE" if unavailable else "RATE_LIMITED"
    )
    assert (await count_effects(rt))["operations"] == 0


async def test_tool_drift_lock_and_reapproval(lab):
    _, issuer, faults, app, _ = lab
    faults["catalog"] = "drift"
    reply = await call(app, issuer, "crm__get_customer", {"customer_id": "cus-a-01"})
    assert reply.structured_content["code"] in {"TOOL_SCHEMA_DRIFT", "TOOL_NOT_AVAILABLE"}
    reply = await call(app, issuer, "crm__get_customer", {"customer_id": "cus-a-01"})
    assert reply.structured_content["code"] == "TOOL_NOT_AVAILABLE"
    detail = await admin(app, issuer, "/api/v1/tools/crm__get_customer")
    assert detail.json()["state"] == "DRIFTED"
    body = REASON | {"fingerprint": detail.json()["candidate_fingerprint"]}
    assert (
        await admin(app, issuer, "/api/v1/tools/crm__get_customer/approve-manifest", body)
    ).status_code == 200
    assert not (await call(app, issuer, "crm__get_customer", {"customer_id": "cus-a-01"})).is_error


async def test_simulator_has_no_side_effects_and_audit_integrity(lab):
    rt, issuer, _, app, _ = lab
    await create_approval(app, issuer, export_args())
    staged = await admin(
        app,
        issuer,
        "/api/v1/policies/drafts",
        REASON | {"config": {"export_requires_approval": False}},
    )
    assert staged.status_code == 201, staged.text
    before = await count_effects(rt)
    replay = await admin(
        app, issuer, "/api/v1/policies/simulate", {"candidate": staged.json()["id"]}
    )
    assert replay.json()["changes"]["allow"] == 1
    assert replay.json()["cases"][0]["regression"]
    assert await count_effects(rt) == before
    validation = await admin(
        app, issuer, f"/api/v1/policies/drafts/{staged.json()['id']}/validate", {}
    )
    assert validation.json()["error"]["code"] == "MANDATORY_EXPORT_REVIEW"
    integrity = await admin(app, issuer, "/api/v1/audit/integrity")
    assert integrity.json()["valid"] and integrity.json()["events"] >= 2
    assert (
        await admin(app, issuer, "/api/v1/audit/events", name="borealis-support")
    ).status_code == 403


@pytest.mark.parametrize(
    "invalid",
    [
        {"effect": "permit"},
        {"effect": "allow"},
        {"effect": "allow", "reason_codes": ["OK"], "approval_policy": None, "obligations": []},
    ],
)
async def test_bad_policy_response(invalid):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"result": invalid}))
    ) as client:
        assert (await OPA("http://invalid", client).evaluate({}, {})).effect == "deny"


@given(
    st.text(alphabet="abcdefghijk", min_size=1, max_size=20).filter(
        lambda key: key != "customer_id"
    )
)
def test_extra_properties_fail(key):
    schema = TOOLS["crm__get_customer"].wire(public=True).input_schema
    assert not Draft202012Validator(schema).is_valid({"customer_id": "cus-a-01", key: "borealis"})


@given(st.integers(min_value=1, max_value=19))
def test_action_hash_changes_with_quantity(number):
    assert digest({"limit": number, "destination": "aurora.example"}) != digest(
        {"limit": number + 1, "destination": "aurora.example"}
    )


def test_domain_normalization_and_dlp():
    assert address("user@AURORA.EXAMPLE")[1] == "aurora.example"
    assert domain("bücher.example") == "xn--bcher-kva.example"
    assert domain("aurora.example.attacker.test") != "aurora.example"
    assert has_sensitive("ＳＳＮ_\u200bＤＥＭＯ")
    assert has_sensitive("000-00-0123")
    with pytest.raises(ValueError):
        address("a@aurora.example@attacker.test")


async def test_policy_activation_requires_second_operator_and_invalidates_old_approval(lab):
    rt, issuer, _, app, _ = lab
    args = export_args()
    approval = await create_approval(app, issuer, args)
    assert (await admin(app, issuer, f"/api/v1/approvals/{approval}/approve", REASON)).is_success
    draft = await admin(
        app, issuer, "/api/v1/policies/drafts", REASON | {"config": {"export_cap": 4}}
    )
    identifier = draft.json()["id"]
    assert (
        await admin(app, issuer, f"/api/v1/policies/drafts/{identifier}/validate", {})
    ).is_success
    path = f"/api/v1/policies/drafts/{identifier}/activate"
    assert (await admin(app, issuer, path, REASON)).status_code == 409
    assert (await admin(app, issuer, path, REASON, name="aurora-reviewer")).is_success
    denied = await call(
        app, issuer, "crm__export_customers", args, name="aurora-lead", approval=approval
    )
    assert denied.structured_content["code"] == "APPROVAL_INVALID"
    assert (await count_effects(rt))["exports"] == 0


async def test_approval_reveal_redaction_and_retention(lab):
    from securemcp.retention import sweep

    rt, issuer, _, app, _ = lab
    args = export_args()
    approval = await create_approval(app, issuer, args)
    path = f"/api/v1/approvals/{approval}/arguments"
    assert (await admin(app, issuer, path, name="aurora-lead")).status_code == 403
    assert (await admin(app, issuer, path)).json() == args
    async with rt.sessions.begin() as db:
        item = await db.get(Approval, approval)
        assert args["idempotency_key"] not in item.encrypted_arguments
        item.expires = now() - 1
    await sweep(rt.sessions, 0)
    async with rt.sessions() as db:
        item = await db.get(Approval, approval)
        assert item.status == "EXPIRED" and item.encrypted_arguments is None


async def test_redirect_and_response_limit():
    from securemcp.wire import BoundedTransport, WireLimit

    endpoint = "https://198.51.100.20/mcp"
    for code, body in ((302, b""), (200, b"x" * 200)):
        upstream = httpx2.MockTransport(
            lambda req: httpx2.Response(
                code, content=body, headers={"Location": "https://untrusted.example/mcp"}
            )
        )
        async with httpx2.AsyncClient(transport=BoundedTransport(upstream, endpoint, 64)) as client:
            if code == 302:
                with pytest.raises(WireLimit):
                    await client.post(endpoint)
            else:
                # The mock transport has already read its own content. Assert the byte
                # stream contract independently of HTTPX's mock response cache.
                from securemcp.wire import BoundedStream

                class Source:
                    async def __aiter__(self):
                        yield body

                with pytest.raises(WireLimit):
                    async for _ in BoundedStream(Source(), 64):
                        pass
            with pytest.raises(WireLimit):
                await client.post("https://untrusted.example/mcp")


async def test_optional_model_adapter_mock():
    from securemcp.agent import ModelAdapter

    def handler(request):
        assert request.url.host == "api.openai.com"
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "docs__read_document",
                                        "arguments": '{"document_id":"doc-a-01"}',
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        choice = await ModelAdapter(http, "test-model", "test-fixture-placeholder").propose(
            "Synthetic document", []
        )
    assert choice == ("docs__read_document", {"document_id": "doc-a-01"})


async def test_input_schema_drift_requires_compatible_restoration(lab):
    _, issuer, faults, app, _ = lab
    name = "crm__get_customer"
    faults["catalog"] = "schema"
    assert (await call(app, issuer, name, {"customer_id": "cus-a-01"})).is_error
    detail = await admin(app, issuer, f"/api/v1/tools/{name}")
    assert detail.json()["state"] == "DRIFTED"
    assert detail.json()["candidate"]["inputSchema"]["additionalProperties"] is True
    review_path = f"/api/v1/tools/{name}/approve-manifest"
    assert (
        await admin(
            app,
            issuer,
            review_path,
            REASON | {"fingerprint": detail.json()["candidate_fingerprint"]},
        )
    ).status_code == 409
    faults["catalog"] = ""
    restored = await admin(app, issuer, f"/api/v1/tools/{name}")
    assert (
        await admin(
            app,
            issuer,
            review_path,
            REASON | {"fingerprint": restored.json()["candidate_fingerprint"]},
        )
    ).is_success
    assert not (await call(app, issuer, name, {"customer_id": "cus-a-01"})).is_error
