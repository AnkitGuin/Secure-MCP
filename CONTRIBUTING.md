# Contributing

Reproduce the workflow locally with the seeded realm. A change to policy facts, approval binding, or upstream behavior should identify the security invariant it changes and exercise the normal MCP or API entry point in a regression test.

Use `make lint`, `make test`, and the relevant Playwright or demo command. Include test output with a review. Apply changes to the bounded policy DTO, Rego policy, and simulator together if their contract changes. Use migrations for persistent schema edits. Keep credentials, synthetic run state, and dependency caches out of commits.
