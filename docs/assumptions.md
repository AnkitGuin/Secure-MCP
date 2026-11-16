# Implementation assumptions

- The uploaded instructions define the repository contract. The local demo uses synthetic CRM case status and notes to represent support tickets.
- Each seed identity has one tenant membership. Multiple active memberships fail closed unless a deployment implements an independently verified tenant selection flow. The console displays the verified tenant.
- Operations use a fixed, allowlisted set of local connector profiles. An operator can register, disable, discover, and approve profiles. An input schema that changes the safe adapter contract requires a coordinated code and policy release before approval.
- Runtime quotas and review-data retention are deployment settings. External domain permissions and export limits are versioned policy settings.
- MCP OAuth discovery is supported with a pre-registered Keycloak client. The demo uses static local client configuration.
- In-process benchmark fixtures use an isolated issuer, database, and credentials. The native stack separately exercises Keycloak, Redis, PostgreSQL and actual loopback MCP transports.
