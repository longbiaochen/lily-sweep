# Unsafe Warehouse Agent Fixture

This fixture is intentionally unsafe. It exists to prove that LilySweep catches:

- shell execution from agent input
- wildcard tool access
- missing human approval, dry-run, and rollback controls
- unguarded actuator routes
- ambiguous simulation vs real-hardware toggles
- forklift / elevator / public-lobby / battery affordances in the scenario
