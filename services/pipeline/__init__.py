"""pipeline: the live ingest -> features -> Jev -> policy -> notifier -> Tier-2
integration layer (docs/architecture.md §2, §12 Phase C task 3 and Phase D task 2).

Unlike most of this repo's other service directories, "pipeline" has no hyphen in
its name, so it *is* reachable via a normal dotted import (`import services.pipeline`)
when the repo root is on `sys.path`. It's still consumed the same flat-import way as
every other service here (`sys.path.insert(0, ".../services/pipeline"); import
run_pipeline`) for consistency with the rest of the repo's convention and because this
package itself reaches into several HYPHENATED sibling service directories
(feature-builder, jev-client, policy-engine, tier2-worker) that have no other way to
be imported -- see run_pipeline.py's module docstring for the exact sys.path setup.

This package is a pure integration/glue layer: it owns no business logic of its own
beyond field-mapping and orchestration. All real decision logic (feature computation,
Jev scoring, policy evaluation, brief generation) lives in and is owned by the
services it wires together.
"""
