"""policy-engine: versioned YAML rules + a small deterministic evaluator.

Decides auto_close / auto_escalate / queued for a Jev decision (docs/architecture.md §8).
Zero network calls, zero DB writes -- evaluator.py is a pure decision function plus a YAML
loader. Notification sending is services/notifier's job; DB writes are the integration
layer's job (a later phase).

Deliberately left without a `from .evaluator import evaluate` re-export: this directory's
name ("policy-engine") contains a hyphen, so it is not reachable via a normal dotted
`import` (`import services.policy-engine` is a syntax error) and a relative import here
would break tooling (e.g. pytest) that tries to import this file directly as part of
collection. Consumers should add this directory to `sys.path` and import directly, e.g.:

    sys.path.insert(0, "<repo_root>/services/policy-engine")
    from evaluator import evaluate, load_policy, PolicyOutcome
"""
