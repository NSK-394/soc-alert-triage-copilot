-- Small key/value settings store, e.g. the dashboard's global Tier-2 provider dropdown
-- (docs/architecture.md §9: "a later iteration adds a dropdown to pick Luna / Sol / Astra
-- per alert or globally"). tier2-worker reads the "tier2_model" key here, falling back to
-- the TIER2_MODEL env var when no row is present.

CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
