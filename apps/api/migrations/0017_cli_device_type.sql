ALTER TABLE cli_login ADD COLUMN device_type TEXT NOT NULL DEFAULT 'cli' CHECK (device_type IN ('cli', 'extension'));
