import asyncio
import base64
import hashlib
import json
import re
import time
import unicodedata
from dataclasses import dataclass
from typing import Any

import httpx
import idna
import jwt
from cryptography.fernet import Fernet
from sqlalchemy import select

from .config import CONNECTORS, Settings
from .db import Membership, PrincipalRecord, Tenant
from .demo_identities import ROLE_SCOPES

SAFE_CODE = re.compile(r"^[A-Z0-9_]{1,64}$")
MARKER = re.compile(
    r"ssn[\W_]*demo|account[\W_]*number[\W_]*demo|secret[\W_]*token[\W_]*demo"
    r"|\b\d{3}-\d{2}-\d{4}\b|\b\+?\d[\d ()-]{8,}\d\b"
    r"|[\w.+-]+@[\w.-]+\.[a-z]{2,}",
    re.I,
)
PII_FIELDS = {"email", "recipient", "ssn_demo", "phone", "account_number_demo", "secret_token_demo"}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def review_cipher(settings: Settings) -> Fernet:
    secret = (
        settings.review_secret.get_secret_value()
        if settings.review_secret
        else ":".join(settings.secret(name) for name in CONNECTORS)
    )
    key = hashlib.sha256(("securemcp-approval-v1:" + secret).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def domain(value: str) -> str:
    if len(value) > 253 or value != value.strip() or value.endswith("."):
        raise ValueError("Invalid domain")
    ascii_name = idna.encode(value, uts46=True, std3_rules=True).decode().lower()
    if "." not in ascii_name or ascii_name.endswith("."):
        raise ValueError("Invalid domain")
    return ascii_name


def address(value: str) -> tuple[str, str]:
    local, sep, suffix = value.partition("@")
    if not sep or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+%-]{0,63}", local) or ".." in local:
        raise ValueError("Invalid destination")
    normalized = domain(suffix)
    return f"{local}@{normalized}", normalized


def has_sensitive(text: str) -> bool:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
    return bool(MARKER.search(normalized))


def redact(data: Any) -> Any:
    if isinstance(data, dict):
        return {
            k: ("[redacted]" if k.casefold() in PII_FIELDS else redact(v)) for k, v in data.items()
        }
    if isinstance(data, list):
        return [redact(v) for v in data]
    if isinstance(data, str) and has_sensitive(data):
        normalized = unicodedata.normalize("NFKC", data)
        normalized = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
        return MARKER.sub("[redacted]", normalized)
    return data


@dataclass(frozen=True)
class Principal:
    sub: str
    name: str
    tenant: str
    roles: frozenset[str]
    scopes: frozenset[str]
    client: str


class AuthError(Exception):
    def __init__(self, code: str = "INVALID_TOKEN", status: int = 401):
        self.code = code
        self.status = status


class OIDC:
    def __init__(self, settings: Settings, sessions, client: httpx.AsyncClient):
        self.cfg = settings
        self.sessions = sessions
        self.http = client
        self.keys: dict[str, Any] = {}
        self.loaded = 0.0
        self.last_attempt = 0.0
        self.lock = asyncio.Lock()

    @property
    def issuer(self):
        return self.cfg.oidc_issuer.rstrip("/")

    @property
    def backchannel(self):
        return (self.cfg.oidc_backchannel or self.issuer).rstrip("/")

    async def refresh(self, kid: str):
        async with self.lock:
            age = time.monotonic() - self.loaded
            if kid in self.keys and age < 120:
                return
            if time.monotonic() - self.last_attempt < 2:
                raise AuthError()
            self.last_attempt = time.monotonic()
            try:
                discovery = await self.http.get(
                    f"{self.backchannel}/.well-known/openid-configuration"
                )
                discovery.raise_for_status()
                metadata = discovery.json()
                jwks = f"{self.issuer}/protocol/openid-connect/certs"
                if (
                    not isinstance(metadata, dict)
                    or metadata.get("issuer") != self.issuer
                    or metadata.get("jwks_uri") != jwks
                ):
                    raise AuthError()
                response = await self.http.get(f"{self.backchannel}/protocol/openid-connect/certs")
                response.raise_for_status()
                candidates = response.json()["keys"]
                if not isinstance(candidates, list) or not 1 <= len(candidates) <= 32:
                    raise AuthError()
                keys = {}
                for candidate in candidates:
                    if not isinstance(candidate, dict):
                        raise AuthError()
                    if (
                        candidate.get("kty") != "RSA"
                        or candidate.get("use") != "sig"
                        or candidate.get("alg") != "RS256"
                    ):
                        continue
                    key_id = candidate.get("kid")
                    if not isinstance(key_id, str) or not 1 <= len(key_id) <= 128 or key_id in keys:
                        raise AuthError()
                    keys[key_id] = jwt.PyJWK.from_dict(candidate, algorithm="RS256").key
                if not keys:
                    raise AuthError()
            except (ValueError, TypeError, KeyError, jwt.PyJWTError, httpx.HTTPError) as error:
                raise AuthError() from error
            # Publish a complete validated snapshot; a broken refresh cannot erase the cache.
            self.keys = keys
            self.loaded = time.monotonic()

    async def verify(self, header: str | None, tenant: str | None = None) -> Principal:
        if not header or not header.startswith("Bearer ") or len(header) > 12000:
            raise AuthError("TOKEN_REQUIRED")
        token = header[7:]
        try:
            alg = jwt.get_unverified_header(token)
            kid = alg.get("kid")
            if alg.get("alg") != "RS256" or not isinstance(kid, str) or len(kid) > 128:
                raise AuthError()
            if kid not in self.keys or time.monotonic() - self.loaded >= 120:
                await self.refresh(kid)
            key = self.keys.get(kid)
            if key is None:
                raise AuthError()
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self.cfg.audience,
                issuer=self.issuer,
                leeway=3,
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
            if claims.get("typ") != "Bearer" or not isinstance(claims.get("scope", ""), str):
                raise AuthError()
        except (ValueError, TypeError, KeyError, jwt.PyJWTError, httpx.HTTPError) as error:
            raise AuthError() from error
        async with self.sessions() as db:
            stmt = (
                select(Membership, PrincipalRecord)
                .join(PrincipalRecord, Membership.sub == PrincipalRecord.sub)
                .join(Tenant, Membership.tenant == Tenant.id)
                .where(
                    Membership.sub == claims["sub"],
                    Membership.enabled.is_(True),
                    PrincipalRecord.enabled.is_(True),
                    Tenant.enabled.is_(True),
                )
            )
            if tenant:
                stmt = stmt.where(Membership.tenant == tenant)
            memberships = (await db.execute(stmt.limit(2))).all()
        if len(memberships) != 1:
            raise AuthError("MEMBERSHIP_REQUIRED", 403)
        m, p = memberships[0]
        allowed = set().union(*(set(ROLE_SCOPES.get(role, "").split()) for role in m.roles))
        return Principal(
            p.sub,
            p.name,
            m.tenant,
            frozenset(m.roles),
            frozenset(claims.get("scope", "").split()) & allowed,
            str(claims.get("azp", "")),
        )
