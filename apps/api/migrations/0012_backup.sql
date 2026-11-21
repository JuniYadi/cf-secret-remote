-- ADR 23: maintenance mode for restore. One row while a restore runs; writes return 503 until it is removed.
-- Not part of backup files (transient state).
CREATE TABLE maintenance (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  since         INTEGER NOT NULL,           -- unix seconds
  by            TEXT NOT NULL               -- identity id of the admin who started the restore
);
