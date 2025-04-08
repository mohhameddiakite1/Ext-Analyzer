# Hazardous Test Extension

This test extension contains multiple security risks to test extraction and analysis capabilities.

## Dangerous `manifest.json` Fields:
- **`permissions`**: Grants excessive access (e.g., tabs, webRequest, scripting).
- **`content_security_policy`**: Allows unsafe inline scripts and external execution.
- **`devtools_page`**: Injects scripts into Chrome DevTools.
- **`side_panel`**: Loads a fake UI for phishing simulations.
- **`web_accessible_resources`**: Allows external sites to load the extension’s scripts.
- **`chrome_settings_override`**: Alters homepage and search settings.
- **`background.js`**: Runs hidden script execution.
- **`commands`**: Registers hidden keyboard shortcuts.
- **`host_permissions`**: Grants full access to external domains.

## Included Malicious Files:
- **`background.js`**: Fetches and executes an external script.
- **`content.js`**: Dynamically injects a script into web pages.
- **`popup.js`**: Uses `document.write` to steal cookies.
- **`injected.js`**: Contains `eval()` for executing arbitrary code.
- **`devtools.js`**: Listens to DevTools events and sends logs to an external server.
- **`side_panel.html`**: Simulates a malicious side panel UI.

## Dependency Analysis:
- **Contains `package.json`** with outdated dependencies (`jquery 1.8.3`, `lodash 3.10.1`).
- **Has an alternative test case where no `package.json` is present** (forcing manual analysis of `.js` files).

## Usage:
Extract the extension and load it as an **unpacked extension** in Chrome/Edge Developer Mode.
