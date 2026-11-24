-- ADR 36: environment key consistency. A collection maps user-defined environment labels to secret paths and
-- declares the expected key names. A declaration holds no value: presence is derived from each mapped path's
-- cleartext `names`, so an unset key is simply a name that is absent from that path's bundle.
-- `revision` is the compare-and-swap guard for every change to the definition.

CREATE TABLE env_collection (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  revision    INTEGER NOT NULL DEFAULT 1,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE env_collection_env (
  collection_id TEXT NOT NULL REFERENCES env_collection(id) ON DELETE CASCADE,
  label         TEXT NOT NULL,
  path          TEXT NOT NULL,
  PRIMARY KEY (collection_id, label),
  UNIQUE (collection_id, path)
);

CREATE TABLE env_collection_key (
  collection_id TEXT NOT NULL REFERENCES env_collection(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  description   TEXT,
  PRIMARY KEY (collection_id, name)
);
