"""Run tests with an isolated, temporary PostgreSQL database in Compose."""

import asyncio
import os
import sys
from uuid import uuid4

import asyncpg
import httpx
from sqlalchemy.engine import make_url


async def main():
    admin = os.environ["SMCP_DATABASE_URL"]
    database = "smcp_test_" + uuid4().hex
    connection = await asyncpg.connect(admin.replace("+asyncpg", ""))
    try:
        await connection.execute(f"CREATE DATABASE {database}")
        async with httpx.AsyncClient(trust_env=False, timeout=1) as client:
            for _ in range(30):
                try:
                    if (await client.get(os.environ["SMCP_OPA_URL"] + "/health")).is_success:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(1)
            else:
                raise SystemExit("OPA failed readiness checks")
        environment = os.environ | {
            "SMCP_TEST_POSTGRES": make_url(admin)
            .set(database=database)
            .render_as_string(hide_password=False)
        }
        test = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "pytest", *sys.argv[1:], env=environment
        )
        status = await test.wait()
    finally:
        await connection.execute(f"DROP DATABASE IF EXISTS {database} WITH (FORCE)")
        await connection.close()
    raise SystemExit(status)


if __name__ == "__main__":
    asyncio.run(main())
