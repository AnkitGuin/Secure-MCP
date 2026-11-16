import time

import httpx
import pytest
from pydantic import ValidationError

from securemcp.config import ConnectorSettings, Settings
from securemcp.policy import OPA
from securemcp.security import OIDC, AuthError


def settings(**overrides):
    return Settings(
        **{
            "database_url": "sqlite+aiosqlite:///unused.db",
            "redis_url": "redis://127.0.0.1:6379",
            "local_demo": True,
            "crm_secret": "c" * 40,
            "docs_secret": "d" * 40,
            "messages_secret": "m" * 40,
            **overrides,
        }
    )


@pytest.mark.parametrize("payload", [None, [], True, "allow", 1, {"result": None}])
async def test_malformed_policy_envelope_denies(payload):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
    ) as client:
        decision = await OPA("http://policy", client).evaluate({}, {})
    assert decision.effect == "deny"
    assert decision.reason_codes == ["POLICY_ENGINE_UNAVAILABLE"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"call_timeout": 0},
        {"call_timeout": -1},
        {"call_timeout": float("inf")},
        {"call_timeout": float("nan")},
        {"max_request": 0},
        {"max_request": -1},
        {"max_request": 100_000_000},
        {"max_response": 0},
        {"max_response": -1},
        {"max_response": 100_000_000},
    ],
)
def test_invalid_runtime_limits_rejected(overrides):
    with pytest.raises(ValidationError):
        settings(**overrides)


@pytest.mark.parametrize("limit", [-1, 0, 100_000_000])
def test_connector_request_limit_rejected(limit):
    with pytest.raises(ValidationError):
        ConnectorSettings(database_url="unused", connector="crm", max_request=limit)


@pytest.mark.parametrize("metadata", [None, [], "issuer", 1])
async def test_malformed_oidc_discovery_rejected(metadata):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=metadata))
    ) as client:
        with pytest.raises(AuthError):
            await OIDC(settings(), None, client).refresh("new-key")


@pytest.mark.parametrize("keys", [[None], ["key"], [{"kid": "x"}], []])
async def test_malformed_jwks_rejected_without_discarding_cached_keys(keys):
    cfg = settings()

    def respond(request):
        if request.url.path.endswith("/certs"):
            return httpx.Response(200, json={"keys": keys})
        return httpx.Response(
            200,
            json={
                "issuer": cfg.oidc_issuer,
                "jwks_uri": cfg.oidc_issuer + "/protocol/openid-connect/certs",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        oidc = OIDC(cfg, None, client)
        cached = {"known-key": object()}
        oidc.keys = cached.copy()
        oidc.loaded = time.monotonic() - 121
        with pytest.raises(AuthError):
            await oidc.refresh("new-key")
        assert oidc.keys == cached
