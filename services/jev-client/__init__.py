"""jev-client: typed-decision Tier-1 scoring client for Jev (docs/architecture.md §5).

Deliberately left without re-exports: this directory's name ("jev-client") contains a
hyphen, so it is not reachable via a normal dotted `import` (`import services.jev-client`
is a syntax error), and a relative import here would break tooling (e.g. pytest) that
tries to import this file directly as part of collection. Consumers should add this
directory to `sys.path` and import the modules directly, e.g.:

    sys.path.insert(0, "<repo_root>/services/jev-client")
    from client import JevClient, JevDecision, JevUnavailableError
    from question_catalog import JevStateObject, QUESTION_CATALOG

See client.py's module docstring for the transport strategy (why this wraps the real
`typesafe-sdk` PyPI package instead of a hand-rolled httpx client) and the fail-safe
contract callers must honor.
"""
