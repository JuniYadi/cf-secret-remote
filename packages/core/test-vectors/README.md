# Test vectors

Fixed inputs and expected outputs for the crypto format. Every consumer must pass the same vectors: the browser, the CLI, and the Worker (for the parts it validates).

A vector is a JSON file with the inputs (keys, plaintext, nonces) and the bytes that must come out, so anything that decrypts in one place decrypts in all of them. Add a vector whenever the format changes.

| File               | Covers                                                                                                                                                                                            | Checked in                                                                 |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `fingerprint.json` | ADR 22 per-name fingerprints: HMAC-SHA256 under the group key over `fp\|<path>\|<NAME>\|<value>`, first 8 bytes in hex. Expected values were cross-checked with `openssl dgst -sha256 -mac HMAC`. | `packages/core/src/core.test.ts`, `apps/cli/src/commands/versions.test.ts` |
