# 13. CLI host, project config and run

Status: accepted

## Decision
Host precedence: `--host` > `CFS_HOST` > `.cfs.json` > `~/.config/cfs/config.json`. `.cfs.json` is `{ "host", "project" }`. `cfs run [secret] -- cmd` uses `<project>/<env>` (env defaults to `dev`) when no secret is given, injects the values into the child's environment only, never writes them to disk, and exits with the child's exit code. `cfs get` prints values; `cfs set NAME=value` merges into the current version and writes a new one.
