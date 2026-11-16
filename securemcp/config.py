from ipaddress import ip_address
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

CONNECTORS = ("crm", "docs", "messages")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SMCP_", extra="ignore")

    database_url: str
    redis_url: str
    opa_url: str = "http://127.0.0.1:8181"
    oidc_issuer: str = "http://localhost:8080/realms/securemcp"
    oidc_backchannel: str | None = None
    audience: str = "securemcp-gateway"
    resource_url: str = "http://localhost:5173/mcp"
    browser_origin: str = "http://localhost:5173"
    public_client: str = "securemcp-console"
    local_demo: bool = False
    crm_url: str = "http://127.0.0.1:8101/mcp"
    docs_url: str = "http://127.0.0.1:8102/mcp"
    messages_url: str = "http://127.0.0.1:8103/mcp"
    crm_secret: SecretStr
    docs_secret: SecretStr
    messages_secret: SecretStr
    review_secret: SecretStr | None = None
    review_retention_days: int = 7
    approval_ttl: int = 300
    call_timeout: float = Field(4.0, gt=0, le=60, allow_inf_nan=False)
    max_request: int = Field(32768, ge=1024, le=1048576)
    max_response: int = Field(65536, ge=1024, le=1048576)
    quota_per_minute: int = 90

    @model_validator(mode="after")
    def secure_defaults(self):
        secrets = [self.secret(name) for name in CONNECTORS]
        if min(map(len, secrets)) < 32 or len(set(secrets)) != 3:
            raise ValueError("Use three distinct connector secrets of at least 32 characters")
        for name in CONNECTORS:
            endpoint = urlsplit(self.endpoint(name))
            if (
                endpoint.scheme not in {"http", "https"}
                or endpoint.path != "/mcp"
                or endpoint.username
                or endpoint.query
                or endpoint.fragment
                or not endpoint.hostname
            ):
                raise ValueError("Invalid configured connector endpoint")
            address = ip_address(endpoint.hostname)
            if (
                address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or address.is_reserved
            ):
                raise ValueError("Forbidden connector endpoint")
            if endpoint.scheme == "http" and (
                not self.local_demo or not (address.is_loopback or address.is_private)
            ):
                raise ValueError("HTTP connectors require explicit local demo mode and private IPs")
        if self.review_secret and len(self.review_secret.get_secret_value()) < 32:
            raise ValueError("Review encryption requires a secret of at least 32 characters")
        if not self.local_demo:
            if not self.review_secret:
                raise ValueError("A dedicated review secret is required")
            public_urls = [self.oidc_issuer, self.resource_url, self.browser_origin]
            if any(urlsplit(url).scheme != "https" for url in public_urls) or self.oidc_backchannel:
                raise ValueError("HTTPS issuer and public URLs are required")
        if (
            not 5 <= self.approval_ttl <= 3600
            or not 1 <= self.quota_per_minute <= 10000
            or not 0 <= self.review_retention_days <= 365
        ):
            raise ValueError("Invalid operational limits")
        return self

    def endpoint(self, name: str) -> str:
        if name not in CONNECTORS:
            raise ValueError("Unknown connector")
        return getattr(self, f"{name}_url")

    def secret(self, name: str) -> str:
        if name not in CONNECTORS:
            raise ValueError("Unknown connector")
        return getattr(self, f"{name}_secret").get_secret_value()


class ConnectorSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SMCP_", extra="ignore")

    database_url: str
    connector: str
    connector_secret: SecretStr | None = None
    max_request: int = Field(32768, ge=1024, le=1048576)

    def secret(self, name: str) -> str:
        if self.connector != name or not self.connector_secret:
            raise ValueError("Connector credential unavailable")
        secret = self.connector_secret.get_secret_value()
        if len(secret) < 32:
            raise ValueError("Connector credential is too short")
        return secret
