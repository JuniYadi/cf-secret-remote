-- ADR 19: daily audit checkpoints, pruning base, and the free-tier usage meter.

-- One row per UTC day, written by the cron before any pruning. `head` is the hash of audit row `seq`.
CREATE TABLE checkpoint (
  day           TEXT PRIMARY KEY,           -- YYYY-MM-DD (UTC)
  seq           INTEGER NOT NULL,           -- audit seq at checkpoint time (0 for an empty chain)
  head          TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

-- Set by pruning. Verification starts from `hash` (the last pruned row), not from genesis.
CREATE TABLE audit_base (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  seq           INTEGER NOT NULL,
  hash          TEXT NOT NULL,
  pruned_at     INTEGER NOT NULL
);

-- Estimate of D1 writes and logged reads per UTC day (D1's own counters are authoritative).
CREATE TABLE usage_day (
  day           TEXT PRIMARY KEY,
  writes        INTEGER NOT NULL DEFAULT 0,
  reads_logged  INTEGER NOT NULL DEFAULT 0
);
