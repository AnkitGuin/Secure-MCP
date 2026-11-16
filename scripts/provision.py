"""Create local-only realm and credentials. Run using the Python standard library."""

import argparse
import json
import os
import secrets
import stat
import tempfile
from pathlib import Path

from securemcp.demo_identities import IDENTITIES, ROLE_SCOPES

SCOPES = sorted(set(" ".join(ROLE_SCOPES.values()).split()))
ROOT = Path(__file__).resolve().parents[1]


def client(client_id, *, interactive=False, direct=False, service=False, secret=None):
    scopes = ROLE_SCOPES["demo_agent"].split() if service else SCOPES
    return {
        "clientId": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": not service,
        "secret": secret,
        "standardFlowEnabled": interactive,
        "directAccessGrantsEnabled": direct,
        "serviceAccountsEnabled": service,
        "redirectUris": ["http://localhost:5173/callback"] if interactive else [],
        "webOrigins": ["http://localhost:5173"] if interactive else [],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": "http://localhost:5173",
        }
        if interactive
        else {},
        "defaultClientScopes": scopes,
        "optionalClientScopes": [],
        "protocolMappers": [
            {
                "name": "Stable subject",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-sub-mapper",
                "config": {"access.token.claim": "true", "id.token.claim": "true"},
            },
            {
                "name": "Gateway audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": "securemcp-gateway",
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                },
            },
        ],
    }


def make_realm(password, agent_secret):
    users = []
    for name, (sub, _tenant, role) in IDENTITIES.items():
        record = {
            "id": sub,
            "username": name,
            "enabled": True,
            "firstName": name,
            "lastName": "Demo",
            "email": f"{name}@securemcp.example",
            "emailVerified": True,
            "realmRoles": [role],
        }
        if role == "demo_agent":
            record.update(
                username="service-account-securemcp-agent", serviceAccountClientId="securemcp-agent"
            )
        else:
            record["credentials"] = [{"type": "password", "value": password, "temporary": False}]
        users.append(record)
    return {
        "realm": "securemcp",
        "enabled": True,
        "displayName": "SecureMCP • Local Lab",
        "accessTokenLifespan": 300,
        "sslRequired": "none",
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "loginWithEmailAllowed": False,
        "bruteForceProtected": True,
        "roles": {"realm": [{"name": name} for name in ROLE_SCOPES]},
        "clients": [
            client("securemcp-console", interactive=True),
            client("securemcp-cli", direct=True),
            client("securemcp-agent", service=True, secret=agent_secret),
        ],
        "clientScopes": [
            {
                "name": scope,
                "protocol": "openid-connect",
                "attributes": {"include.in.token.scope": "true"},
            }
            for scope in SCOPES
        ],
        "users": users,
    }


def write_config(path, content, mode):
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
        if os.name == "posix":
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def provision(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix" and stat.S_IMODE(directory.stat().st_mode) & 0o077:
        raise ValueError(f"Make the demo configuration directory private (chmod 700): {directory}")
    env = directory / "secrets.env"
    values = (
        dict(line.split("=", 1) for line in env.read_text(encoding="utf-8").splitlines() if line)
        if env.exists()
        else {}
    )
    for key in (
        "POSTGRES_PASSWORD",
        "SMCP_DB_GATEWAY_PASSWORD",
        "SMCP_DB_CRM_PASSWORD",
        "SMCP_DB_DOCS_PASSWORD",
        "SMCP_DB_MESSAGES_PASSWORD",
        "DEMO_PASSWORD",
        "DEMO_AGENT_SECRET",
        "SMCP_REVIEW_SECRET",
        "SMCP_CRM_SECRET",
        "SMCP_DOCS_SECRET",
        "SMCP_MESSAGES_SECRET",
    ):
        if key not in values:
            values[key] = secrets.token_urlsafe(32)
    contents = "".join(f"{key}={value}\n" for key, value in values.items())
    if not env.exists() or env.read_text(encoding="utf-8") != contents:
        write_config(env, contents, 0o600)
    elif os.name == "posix":
        env.chmod(0o600)
    realm = directory / "securemcp-realm.json"
    definition = json.dumps(
        make_realm(values["DEMO_PASSWORD"], values["DEMO_AGENT_SECRET"]), indent=2
    )
    # Docker mounts this file directly. Keycloak's container UID can differ from the host UID.
    if not realm.exists() or realm.read_text(encoding="utf-8") != definition:
        write_config(realm, definition, 0o644)
    elif os.name == "posix":
        realm.chmod(0o644)
    return values


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=ROOT / ".local")
    args = parser.parse_args()
    provision(args.directory)
    print(f"Local demo configuration generated in {args.directory}")
