-- ADR 27: fixed-window counters for rate limits. Old windows are swept by cron (ADR 19).
CREATE TABLE login_attempt (
  key     TEXT NOT NULL,       -- e.g. "approle:<role_id>", "cli-approve:<identity_id>"
  window  INTEGER NOT NULL,    -- start of the window, unix seconds
  count   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key, window)
);
