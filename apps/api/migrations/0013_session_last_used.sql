-- ADR 24 (Devices): when a session was last used. Written at most once per 10 minutes per session, so
-- ordinary traffic does not spend the free-tier write quota. Null for sessions that predate this column.
ALTER TABLE session ADD COLUMN last_used_at INTEGER;
