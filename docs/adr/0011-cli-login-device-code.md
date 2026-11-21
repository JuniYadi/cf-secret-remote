# 11. CLI login for people: device code

Status: accepted

## Context
The CLI cannot hold an Access cookie, and a loopback port is fragile over SSH and in containers.

## Decision
`cfs login` calls `POST /api/v1/cli/start`, shows a short code (`ABCD-EFGH`) and a URL, and polls `POST /api/v1/cli/poll`. The person opens the URL in the browser, signs in through Access, and approves with `POST /api/v1/cli/approve`. The poll then returns a `cfs_` token (8 hours). Codes live 10 minutes, are single use, and only a hash of the device code is stored.

## Consequences
The approve screen is the Cli-Authorize board in the design. Until the web app exists, approval can be sent by any authenticated client.
