# Native verification

Use this path when PostgreSQL, Redis, Keycloak and OPA are installed directly. Run the services on loopback, and generate a local realm with `python -m scripts.provision`. The observed native environment used Python 3.12.14, PostgreSQL 16.13, Redis 7.4.7, Keycloak 26.6.3, Open Policy Agent 1.8.0, and MCP Python SDK 2.3.0.

Start Keycloak with the realm file under `data/import` and use `kc.sh start-dev --import-realm --http-host=127.0.0.1 --hostname=http://localhost:8080`. Start OPA with `opa run --server --addr 127.0.0.1:8181 policy/access.rego`. Use PostgreSQL port 55439 and Redis port 56391 to match the optional environment script. Create a database named `securemcp` and set the DSN for your local role.

```sh
uv sync --frozen
export SMCP_DATABASE_URL=postgresql+asyncpg://agent@127.0.0.1:55439/securemcp
source scripts/native-env.sh
uv run alembic upgrade head
uv run python -m securemcp.seed
```

Run the following in separate terminals with the same environment.

```sh
SMCP_CONNECTOR=crm uv run uvicorn securemcp.upstream:app_factory --factory --port 8101
SMCP_CONNECTOR=docs uv run uvicorn securemcp.upstream:app_factory --factory --port 8102
SMCP_CONNECTOR=messages uv run uvicorn securemcp.upstream:app_factory --factory --port 8103
uv run uvicorn securemcp.gateway:app_factory --factory --port 8000
cd frontend && npm ci && npm run dev
```

For backend integration tests, create a dedicated empty PostgreSQL database and point `SMCP_TEST_POSTGRES` at it. Use `uv run pytest -q`. To exercise the HTTP stack without the frontend proxy, set `SMCP_GATEWAY_HTTP=http://127.0.0.1:8000` before the smoke and demo commands. Use `PLAYWRIGHT_CHROMIUM_EXECUTABLE` to select an installed Chromium executable when appropriate.

## Production frontend and proxy verification

The clean native run built the frontend with `npm ci` and `npm run build`, then served `frontend/dist` using Nginx 1.28.1 and `frontend/nginx.conf`. The native Nginx configuration used listener `127.0.0.1:5173`, upstream `127.0.0.1:8000`, and the absolute `frontend/dist` path. It preserved the shipping proxy routes and security headers. A request to `/health/ready` succeeded through the proxy, and `/tools` served the application shell with the Content Security Policy header. SDK smoke, demo, and Playwright all used `http://localhost:5173`.

The PostgreSQL database was initialized with password authentication, migrations, seed data, and distinct gateway and connector roles. Keycloak imported a freshly generated realm and the gateway used its loopback backchannel URL while validating the public issuer. Compose 2.39.4 validated the configuration separately, and registries returned manifests for all eight base image tags on `amd64` and `arm64`.
