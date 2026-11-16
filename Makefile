SHELL := /bin/bash
COMPOSE := docker compose --env-file .local/secrets.env

.PHONY: bootstrap up down smoke demo test test-security test-e2e benchmark lint
bootstrap:
	python -m scripts.provision
	$(COMPOSE) up --build --wait --wait-timeout 240
up:
	$(COMPOSE) up --build --wait --wait-timeout 240
down:
	$(COMPOSE) down
smoke:
	set -a; source .local/secrets.env; set +a; uv run --frozen python -m scripts.client smoke
demo:
	set -a; source .local/secrets.env; set +a; uv run --frozen python -m scripts.client demo
test:
	$(COMPOSE) --profile test run --build --rm tests
test-security:
	$(COMPOSE) --profile test run --build --rm tests python -m scripts.test_stack -q tests/test_security.py
test-e2e:
	set -a; source .local/secrets.env; set +a; cd frontend && npm run test:e2e
benchmark:
	$(COMPOSE) exec -T gateway python -m securemcp.lab --output /tmp/securemcp-report
	$(COMPOSE) cp gateway:/tmp/securemcp-report/. benchmark/reports
lint:
	uv run --frozen ruff check .
	uv run --frozen ruff format --check .
	cd frontend && npm run lint && npm run build
