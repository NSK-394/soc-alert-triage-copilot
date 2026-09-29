"""feature-builder: pure-Python computation of the Jev state object's `derived` fields.

This package has no I/O and no side effects. Every function takes plain data in
and returns plain data out — see `derived_fields.py` for the individual field
computations and `build_derived` for the top-level assembly function.

Deliberately left without a `from .derived_fields import build_derived`
re-export: this directory's name ("feature-builder") contains a hyphen, so it
is not reachable via a normal dotted `import` (`import services.feature-builder`
is a syntax error) and a relative import here would break tooling (e.g.
pytest) that tries to import this file directly as part of collection.
Consumers should add this directory to `sys.path` and `import derived_fields`
directly, e.g.:

    sys.path.insert(0, "<repo_root>/services/feature-builder")
    from derived_fields import build_derived
"""
