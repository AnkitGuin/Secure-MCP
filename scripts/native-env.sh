#!/usr/bin/env bash
# Source from the repository root after provisioning. Ports are configurable.
set -a
source .local/secrets.env
SMCP_LOCAL_DEMO=true
SMCP_DATABASE_URL="${SMCP_DATABASE_URL:-postgresql+asyncpg://agent@127.0.0.1:55439/securemcp}"
SMCP_REDIS_URL="${SMCP_REDIS_URL:-redis://127.0.0.1:56391/0}"
set +a
