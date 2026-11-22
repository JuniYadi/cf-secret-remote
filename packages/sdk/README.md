# @cfs/sdk

Private workspace package for Node and Bun; not published yet. Set `CFS_KIT` to an AppRole kit with access to the account's group, or pass `kitPath` to `getAccount`.

For example, in Playwright `globalSetup`:

```ts
import { getAccount } from "@cfs/sdk";

export default async function globalSetup() {
  const account = await getAccount({
    name: "shop",
    env: "staging",
    role: "admin",
    purpose: process.env.CI_RUN_ID,
  });
  // Use account.username, account.password and await account.totp() in the test runner.
}
```

Give credentials to the test runner, not to an LLM. Do not give agents raw passwords (ADR 35).
