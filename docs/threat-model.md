# Threat model

## Chrome extension

The unlocked key is stored in `chrome.storage.session` with its `lockAt` deadline. An expired key may remain in session storage (memory only, cleared on browser close) until the next extension action, but is never used after `lockAt`. While the popup is open, a timer clears it at the deadline.
