-- ADR 17: agent rules. One row per (app, alias). The proxy reads its own rows and injects the value of `name`
-- from the secret at `secret_path`, sent to `upstream` (https only) as described by `inject`.
-- No plaintext value is stored here. max_reads_per_hour is enforced server-side on each secret fetch.
CREATE TABLE agent_rule (
  identity_id        TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  alias              TEXT NOT NULL,
  secret_path        TEXT NOT NULL,
  name               TEXT NOT NULL,              -- the value name inside the secret (NAME=value)
  upstream           TEXT NOT NULL,              -- https base URL, the only host the proxy talks to
  inject             TEXT NOT NULL,              -- header:Name:Template-with-{value} or query:name
  max_reads_per_hour INTEGER NOT NULL CHECK (max_reads_per_hour BETWEEN 1 AND 100000),
  require_reason     INTEGER NOT NULL DEFAULT 0 CHECK (require_reason IN (0,1)),
  require_approval   INTEGER NOT NULL DEFAULT 0 CHECK (require_approval IN (0,1)),
  PRIMARY KEY (identity_id, alias)
);

CREATE INDEX idx_agent_rule_path ON agent_rule(identity_id, secret_path);
