# Deployment hardening

The Compose stack is scoped to loopback and synthetic data. It uses separate PostgreSQL login roles, generated connector secrets, a generated local realm, and least-capability application containers. The Keycloak password grant and development HTTP listener exist for local demonstration.

For a deployed service, use HTTPS, approved browser origins, proper OAuth client registration, separate secret-manager keys, and a dedicated identity lifecycle. Use server TLS certificates matching pinned connector addresses and restrict the connector network so agents cannot bypass the gateway. Replace the local private bridge with production ingress and network policies. Review any policy that permits external destinations.

Set `SMCP_LOCAL_DEMO=false` and provision `SMCP_REVIEW_SECRET`, production URLs, Redis, a protected PostgreSQL endpoint, and the trusted issuer. Rotate connector secrets with a coordinated gateway/connector release. Key rotation for review encryption requires preserving access to still-live records or explicitly expiring the outstanding review queue.

Store independent audit checkpoints or an external append-only copy and define retention and backup procedures. Encrypted approval payloads are purged after the configured review-data retention period. Plan recovery for the IdP, database, Redis, and policy engine. Add distributed ingress rate controls, alerting, dependency review, and independent security testing before connecting real business tools.
## Validated request limits

Gateway and connector request limits must be between 1 KiB and 1 MiB. The gateway response limit has the same range, and connector call timeouts must be finite, positive, and at most 60 seconds. Invalid settings stop startup. Defaults remain 32 KiB requests, 64 KiB responses, and a four-second connector deadline. These bounds do not replace ingress connection and rate controls.

