FROM ghcr.io/astral-sh/uv:0.10.9 AS uv
FROM python:3.12.14-slim AS runtime
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY securemcp securemcp
COPY migrations migrations
COPY alembic.ini ./
COPY scripts scripts
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid 10001 --no-create-home app
ENV PATH="/app/.venv/bin:$PATH"
USER 10001:10001
CMD ["uvicorn","securemcp.gateway:app_factory","--factory","--host","0.0.0.0","--port","8000","--limit-concurrency","128","--no-access-log"]


FROM runtime AS test
USER root
RUN uv sync --frozen --no-install-project
COPY tests tests
ENV PYTEST_ADDOPTS="-o cache_dir=/tmp/pytest-cache" HYPOTHESIS_STORAGE_DIRECTORY=/tmp/hypothesis
USER 10001:10001

FROM runtime AS app
