"""Provision application login roles on the dedicated local PostgreSQL database."""

import asyncio
import os

import asyncpg

CONTROL = (
    "tenants",
    "principals",
    "memberships",
    "connectors",
    "tool_manifests",
    "policy_versions",
    "policy_grants",
    "tenant_state",
    "approval_requests",
    "approval_reviews",
    "execution_records",
    "policy_simulations",
    "benchmark_scenarios",
    "benchmark_runs",
    "benchmark_results",
)
GRANTS = {
    "gateway": {
        "SELECT, INSERT, UPDATE": CONTROL,
        "SELECT, INSERT": ("audit_events",),
        "SELECT": ("customers", "documents", "upstream_operations"),
    },
    "crm": {
        "SELECT, UPDATE": ("customers",),
        "INSERT": ("notes", "exports"),
        "SELECT, INSERT, UPDATE": ("upstream_operations",),
    },
    "docs": {"SELECT": ("documents",)},
    "messages": {
        "SELECT, INSERT": ("messages",),
        "SELECT, INSERT, UPDATE": ("upstream_operations",),
    },
}


async def main():
    connection = await asyncpg.connect(os.environ["SMCP_DATABASE_URL"].replace("+asyncpg", ""))
    try:
        async with connection.transaction():
            for service, grants in GRANTS.items():
                login = "smcp_" + service
                password = os.environ[f"SMCP_DB_{service.upper()}_PASSWORD"]
                exists = await connection.fetchval(
                    "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname = $1)", login
                )
                command = "ALTER ROLE" if exists else "CREATE ROLE"
                statement = await connection.fetchval(
                    f"SELECT format('{command} %I LOGIN PASSWORD %L', $1::text, $2::text)",
                    login,
                    password,
                )
                await connection.execute(statement)
                await connection.execute(f"GRANT USAGE ON SCHEMA public TO {login}")
                for privileges, tables in grants.items():
                    await connection.execute(
                        f"GRANT {privileges} ON {', '.join(tables)} TO {login}"
                    )
    finally:
        await connection.close()


if __name__ == "__main__":
    asyncio.run(main())
