# cfs Chrome extension

Download `cfs-extension.zip` and `SHA256SUMS` from the same GitHub release. In the directory containing both files, verify the zip before extracting it:

```sh
shasum -a 256 cfs-extension.zip
```

Compare the printed hash with the `cfs-extension.zip` line in `SHA256SUMS`; they must match. Extract the zip. Alternatively, build locally with `bun install --frozen-lockfile` and `bun run --filter @cfs/extension build`, which produces `apps/extension/dist`.

In Chrome, open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select the extracted directory or `apps/extension/dist` from the local build.

Enter the Worker origin, grant access, and approve the displayed device code in the web app. Reopen the popup after approving if it closed. Unlock with your vault password. Open the popup or press Ctrl+Shift+Y (Command+Shift+Y on macOS), then choose a matching Login to fill. Refresh requests the encrypted list again; the extension does not poll for Login updates.

The permissions are:

- `storage`: encrypted cached Logins and memory-only session credentials.
- `activeTab`: access to the current page after the user invokes the extension.
- `scripting`: inject the fill function on demand.
- Optional host access: connect to the Worker origin entered at setup, after the user grants it.

There is no `<all_urls>` permission or always-on content script: the extension only accesses the active page after a user action. Fill is limited to the top frame and an exact HTTPS origin, with HTTP allowed for localhost and 127.0.0.1.

The unlocked key expires after one hour. An expired key may remain in `chrome.storage.session` (memory only, cleared on browser close) until the next extension action, but it is never used after `lockAt`. While the popup is open, a timer clears it at the deadline. Use Lock to clear it sooner.
