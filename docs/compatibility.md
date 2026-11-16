# MCP compatibility

| Path | SDK | Protocol | Verification |
|---|---|---|---|
| Default external SDK discovery | Python MCP 2.3.0 | 2026-07-28 | `python -m scripts.client smoke` |
| Legacy SDK mode | Python MCP 2.3.0 | 2025-11-25 | `python -m scripts.client smoke` |
| Header/body inconsistency | Python MCP 2.3.0 transport | 2026-07-28 | `pytest -k header_mismatch` |
| Gateway-to-connector identity and calls | Python MCP 2.3.0 SDK Client | 2026-07-28 | Native smoke and demo, plus connector tests |

Tools are the advertised application capability. MCP tool metadata carries the optional `securemcp.local/approval` UUID. Write tools take an `idempotency_key` in their public input schema. Gateway credentials stay on the client boundary. The gateway creates a separate short-lived service token and passes an internally generated `operation_id` to the connector.

`GET /.well-known/oauth-protected-resource/mcp` returns the authorization server and resource URL. Callers receive a bearer challenge when missing or presenting an invalid token. The demo resource URL uses the same-origin console proxy. The SDK implements Streamable HTTP message handling, routing header validation, and legacy initialization.

Primary references are the [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28), the [official Python SDK](https://py.sdk.modelcontextprotocol.io/), and [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728).
