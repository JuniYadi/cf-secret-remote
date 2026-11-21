-- ADR 18: alerts and notifications.

-- Admin settings, e.g. alerts.webhook_url (admin-only; the API returns it masked) and alerts.rules.
CREATE TABLE setting (
  key           TEXT PRIMARY KEY,
  value         TEXT NOT NULL
);

-- One row per (rule, subject) for the 15 minute dedupe window.
CREATE TABLE alert_state (
  rule          TEXT NOT NULL,
  subject       TEXT NOT NULL,
  last_sent_at  INTEGER NOT NULL,
  PRIMARY KEY (rule, subject)
);

-- Identity as a column, so the burst and new-network checks can use an index. Filled from the entry JSON for old rows.
ALTER TABLE audit ADD COLUMN who TEXT;
UPDATE audit SET who = json_extract(entry, '$.who');
CREATE INDEX idx_audit_who_at ON audit(who, at);
