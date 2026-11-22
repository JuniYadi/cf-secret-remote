# cfs Chrome extension

Build with `bun install --frozen-lockfile` and `bun run --filter @cfs/extension build`. In Chrome, open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select `apps/extension/dist`. The release zip contains the same unpacked files.

Enter the Worker origin, grant access, and approve the displayed device code in the web app. Reopen the popup after approving if it closed. Unlock with your vault password. Open the popup or press Ctrl+Shift+Y (Command+Shift+Y on macOS), then choose a matching Login to fill. Refresh requests the encrypted list again; the extension does not poll for Login updates.

The extension requests `storage` for encrypted cached Logins and session credentials, `activeTab` to access the current page after the action, and `scripting` to inject the fill function on demand. Optional host access is requested for the Worker entered at setup. There is no always-on content script. Fill is limited to the top frame and an exact HTTPS origin, with HTTP allowed for localhost and 127.0.0.1.

The unlocked key expires after one hour. Expiration is enforced when the popup is open or next opened; Chrome may leave the expired key in session storage until the popup is opened again. Closing the browser clears session storage. Use Lock to clear it sooner.
