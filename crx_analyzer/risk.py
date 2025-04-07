from typing import Union
from .models import (
    ChromePermission,
    RiskLevel,
    RiskReport,
    RiskMapping,
    ExternallyConnectable,
)
from .extension import Extension
from typing import Any, Dict, Union
import requests
import packaging.version
import re
from urllib.parse import urlparse


# credit to https://crxcavator.io/docs.html#/risk_breakdown?id=permissions-breakdown
risk_vector_map = {
    RiskLevel.NONE: [
        ChromePermission.ALARMS,
        ChromePermission.BROWSING_DATA,
        ChromePermission.CONTEXT_MENUS,
        ChromePermission.DECLARATIVE_CONTENT,
        ChromePermission.ENTERPRISE_DEVICE_ATTRIBUTES,
        ChromePermission.FILE_BROWSER_HANDLER,
        ChromePermission.FONT_SETTINGS,
        ChromePermission.GCM,
        ChromePermission.IDLE,
        ChromePermission.POWER,
        ChromePermission.SESSIONS,
        ChromePermission.SYSTEM_CPU,
        ChromePermission.SYSTEM_DISPLAY,
        ChromePermission.SYSTEM_MEMORY,
        ChromePermission.TTS,
        ChromePermission.UNLIMITED_STORAGE,
        ChromePermission.WALLPAPER,
        "side_panel",  # Exists but JS analysis determines risk
    ],
    RiskLevel.LOW: [
        ChromePermission.ACTIVE_TAB,
        ChromePermission.BACKGROUND,
        ChromePermission.CERTIFICATE_PROVIDER,
        ChromePermission.DOCUMENT_SCAN,
        ChromePermission.ENTERPRISE_PLATFORM_KEYS,
        ChromePermission.IDENTITY,
        ChromePermission.NOTIFICATIONS,
        ChromePermission.PLATFORM_KEYS,
        ChromePermission.PRINTER_PROVIDER,
        ChromePermission.WEB_REQUEST_BLOCKING,
        "devtools_page",  # Presence flagged as LOW risk
    ],
    RiskLevel.MEDIUM: [
        ChromePermission.BOOKMARKS,
        ChromePermission.CLIPBOARD_WRITE,
        ChromePermission.DOWNLOADS,
        ChromePermission.FILE_SYSTEM_PROVIDER,
        ChromePermission.GEOLOCATION,
        ChromePermission.MANAGEMENT,
        ChromePermission.NATIVE_MESSAGING,
        ChromePermission.PROCESSES,
        ChromePermission.STORAGE,
        ChromePermission.SYSTEM_STORAGE,
        ChromePermission.TOP_SITES,
        ChromePermission.TTS_ENGINE,
        ChromePermission.WEB_NAVIGATION,
        "background",  # Just flags persistent execution, JS analysis checks real risk
        "chrome_url_overrides",
    ],
    RiskLevel.HIGH: [
        ChromePermission.CLIPBOARD_READ,
        ChromePermission.CONTENT_SETTINGS,
        ChromePermission.DECLARATIVE_NET_REQUEST,
        ChromePermission.DESKTOP_CAPTURE,
        ChromePermission.DISPLAY_SOURCE,
        ChromePermission.DNS,
        ChromePermission.EXPERIMENTAL,
        ChromePermission.HISTORY,
        ChromePermission.PAGE_CAPTURE,
        ChromePermission.PRIVACY,
        ChromePermission.PROXY,
        ChromePermission.TAB_CAPTURE,
        ChromePermission.TABS,
        ChromePermission.VPN_PROVIDER,
        "https://*/*",
        "http://*/*",
        "file:///*",
    ],
    RiskLevel.CRITICAL: [
        ChromePermission.COOKIES,
        ChromePermission.DEBUGGER,
        ChromePermission.WEB_REQUEST,
        ChromePermission.DECLARATIVE_WEB_REQUEST,
        "<all_urls>",
        "*://*/:",
        "*://*/*",
    ],
}

# credit to https://crxcavator.io/docs.html#/risk_breakdown?id=permissions-breakdown
risk_score_map = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 5,
    RiskLevel.MEDIUM: 10,
    RiskLevel.HIGH: 15,
    RiskLevel.CRITICAL: 45,
}


def get_risk_score(risk_level: RiskLevel) -> int:
    return risk_score_map[risk_level]


def get_risk_level(permission: Union[ChromePermission, str]) -> RiskLevel:
    for risk_level, permission_list in risk_vector_map.items():
        if permission in permission_list:
            return risk_level
    return RiskLevel.NONE


RISK_COMMENTS = {
    # Dynamic Script Execution
    "dynamic_script_execution": (
        "The extension uses risky JavaScript patterns such as eval, document.write, or new Function, which can enable arbitrary code execution if not properly sanitized."
    ),

    # Manifest Fields
    "background": (
        "Persistent background pages can maintain long-lived scripts, increasing the attack surface for malicious behavior."
    ),
    "devtools_page": (
        "DevTools pages can inspect and interact with webpages, potentially used for spying or data exfiltration."
    ),
    "side_panel": (
        "Side panels may be used to inject or display unauthorized content alongside legitimate pages."
    ),
    "content_scripts": (
        "Statically declared content scripts may target a wide range of URLs. If match patterns are too broad or include wildcards, "
        "they can be used to monitor or modify web content without user consent."
    ),
    "chrome_url_overrides": (
        "Overriding Chrome's default pages (e.g., new tab, history) can mislead users by displaying unwanted ads or phishing content."
    ),
    "chrome_settings_overrides": (
        "Modifying search engines or startup pages may redirect users to phishing or adware websites."
    ),
    "commands": (
        "Extensions can register hotkeys to trigger background actions. If misused, they can enable stealthy malicious behaviors without user awareness."
    ),
    "content_security_policy": (
        "Weak or permissive content security policies (e.g., allowing 'unsafe-eval') can expose the extension to script injection or execution of malicious code."
    ),
    "externally_connectable": (
        "Allows external web pages or apps to send messages to the extension. This can be abused for command-and-control channels or data exfiltration."
    ),
    "web_accessible_resources": (
        "This allows extension files to be accessed by webpages. If poorly scoped or if sensitive scripts are exposed, it can lead to unauthorized access or script injection."
    ),
}

PERMISSION_RISK_COMMENTS = {
    # --- NONE ---
    "side_panel": "Low-risk UI integration; dangerous behavior depends on associated JS activity.",

    # --- LOW ---
    "devtools_page": "Grants access to Chrome DevTools, may allow interception of developer network data.",
    ChromePermission.ACTIVE_TAB: "Grants temporary access to the active tab, limited in duration and scope.",
    ChromePermission.NOTIFICATIONS: "Can show popups; risk arises with spam or phishing prompts.",
    ChromePermission.BACKGROUND: "Allows persistent background tasks; execution risk depends on script behavior.",
    ChromePermission.WEB_REQUEST_BLOCKING: "Enables synchronous request blocking — risky only when paired with modification logic.",

    # --- MEDIUM ---
    ChromePermission.STORAGE: "Can hold sensitive tokens or credentials if misused.",
    ChromePermission.CLIPBOARD_WRITE: "May overwrite user clipboard, potentially with malicious content.",
    ChromePermission.DOWNLOADS: "Can initiate or alter file downloads — possible vector for malware.",
    ChromePermission.GEOLOCATION: "May track physical location; privacy risk based on use context.",
    ChromePermission.NATIVE_MESSAGING: "Enables communication with native apps — powerful if abused.",
    ChromePermission.MANAGEMENT: "Allows reading extension info; can detect or affect other extensions.",
    "background": "Allows persistent background service; may be used for tracking or stealthy execution.",
    "chrome_url_overrides": "Overrides default Chrome pages like 'newtab'; can mislead users or inject tracking.",

    # --- HIGH ---
    ChromePermission.CLIPBOARD_READ: "May access sensitive clipboard content (e.g., passwords, crypto keys).",
    ChromePermission.TABS: "Can inspect and manipulate open tabs, enabling surveillance or injection.",
    ChromePermission.CONTENT_SETTINGS: "Can override site settings like JS/CSS permissions — used to bypass restrictions.",
    ChromePermission.DECLARATIVE_NET_REQUEST: "Used to filter or rewrite network requests — impacts privacy and content.",
    ChromePermission.HISTORY: "Accesses full browsing history; often used for profiling or data theft.",
    ChromePermission.PROXY: "Can redirect or inspect all web traffic via proxy configuration.",
    ChromePermission.DESKTOP_CAPTURE: "Captures screen or window content; potential for surveillance or data leak.",
    "https://*/*": "Wildcard host permission — grants broad access to HTTPS pages.",
    "http://*/*": "Wildcard host permission — grants broad access to HTTP pages.",
    "file:///*": "Access to local files — extremely sensitive if paired with exfiltration logic.",

    # --- CRITICAL ---
    ChromePermission.COOKIES: "Access to site cookies; can hijack sessions or leak sensitive auth tokens.",
    ChromePermission.DEBUGGER: "Full debugging control over tabs — extremely powerful and abusable.",
    ChromePermission.WEB_REQUEST: "Intercept and modify all requests — commonly misused for surveillance or tampering.",
    ChromePermission.DECLARATIVE_WEB_REQUEST: "Legacy alternative to `webRequest`; allows modification of requests without code.",
    "<all_urls>": "Complete access to all URLs — requires strong justification and verification.",
    "*://*/:": "Malformed or nonstandard wildcard — may indicate sloppy or overly permissive configuration.",
    "*://*/*": "Generic wildcard — indicates total access to all protocols and hosts."
}


def check_domain_urlhaus(domain: str) -> bool:
    """
    Check if the given domain is known to be malicious using the URLhaus API.

    Parameters:
      domain (str): The domain to check (e.g., "evil.com")

    Returns:
      bool: True if the domain is listed as malicious by URLhaus, False otherwise.

    URLhaus is a public threat intelligence service provided by abuse.ch.
    It offers an API that does not require an API key for host lookup.
    """
    endpoint = "https://urlhaus.abuse.ch/api/v1/host/"
    payload = {"host": domain}

    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        response.raise_for_status()
        data = response.json()
        # URLhaus returns a 'query_status' key; if 'ok' and 'urls' is non-empty, the host is malicious.
        if data.get("query_status") == "ok" and data.get("urls"):
            return True
        return False
    except Exception as e:
        print(f"Error checking domain {domain}: {e}")
        return False


# https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy?hl=en
# some cute convo's
# https://stackoverflow.com/questions/37298608/content-security-policy-the-pages-settings-blocked-the-loading-of-a-resource
def evaluate_csp(csp_value: Union[dict, str]) -> RiskLevel:
    """ 
    Evaluate Content Security Policy (CSP) rules for potential security risks. 

    Safe Examples:
    "default-src 'self'; script-src 'self'"  -> RiskLevel.NONE (Restricts to self)

    High-Risk Examples:
    "default-src *"        -> RiskLevel.CRITICAL (Allows all resources from any domain)
    "script-src *"         -> RiskLevel.CRITICAL (Allows scripts from any source)
    "script-src 'unsafe-eval'"  -> RiskLevel.HIGH (Allows eval(), vulnerable to XSS)
    "script-src 'unsafe-inline'" -> RiskLevel.HIGH (Allows inline scripts, XSS risk)

    Sandbox-Specific Risks:
    "sandbox": "script-src 'unsafe-eval'" -> RiskLevel.LOW (Eval allowed in sandbox)
    "sandbox": "default-src *" -> RiskLevel.LOW (Loads resources from anywhere)
    """

    # convert to lowercase for case insensitive check
    if isinstance(csp_value, dict):
        extension_policies = csp_value.get("extension_pages", "").lower()
        sandbox_policies = csp_value.get("sandbox", "").lower()
    elif isinstance(csp_value, str):
        extension_policies = csp_value.lower()
        sandbox_policies = ""
    else:
        return RiskLevel.NONE  # Invalud csp format, assume no risk

    # checking extension_pages csp as  it affects main extension security
    if "default-src *" in extension_policies or "script-src *" in extension_policies:  # allows scripts from all domain's
        return RiskLevel.CRITICAL
    # allows inline scripts or eval() xss
    if "'unsafe-eval'" in extension_policies or "'unsafe-inline'" in extension_policies:
        return RiskLevel.HIGH
    # check csp sandbox (less impactful)
    if "'unsafe-eval'" in sandbox_policies or "'unsafe-inline'" in sandbox_policies:
        return RiskLevel.LOW  # sandboxed eval is not ideal but not highly dangerous
    if "default-src *" in sandbox_policies or "script-src *" in sandbox_policies:
        return RiskLevel.LOW  # sandboxed loading scripts from anywhere is weak but contained

    return RiskLevel.NONE


def evaluate_externally_connectable(value: ExternallyConnectable) -> RiskLevel:
    # need that functionality to scan url's for if a trusted source
    # should i add url's from manifest to checkable field in here or in extensions capabilities
    """
    Evaluate externally_connectable patterns.

    Valid examples:
      "*://example.com/"      -> valid
      "http://*.example.org/*" -> valid
      "https://example.com/*"  -> valid

    Invalid examples:
      "*://example.com/one/"  -> invalid (path too deep)
      "<all_urls>"            -> invalid (overly broad)
      "http://*/*"            -> invalid (wildcard host)
    """
    matches = value.matches

    if not matches:
        return RiskLevel.NONE

    for pattern in matches:
        normalized = pattern.strip()

        # Directly reject <all_urls>
        if normalized in {"<all_urls>", "*://*/*"}:
            return RiskLevel.CRITICAL

        # Check valid schemes. We allow either an explicit scheme or a wildcard scheme.
        if normalized.startswith("*://"):
            # Remove the wildcard scheme marker.
            remainder = normalized[4:]
            host, sep, path = remainder.partition("/")
            if not sep:
                # Missing path separator.
                return RiskLevel.HIGH
            # For a wildcard scheme, only a root-level path is allowed.
            if path not in ("", "/"):
                return RiskLevel.HIGH
        elif normalized.startswith("http://") or normalized.startswith("https://"):
            # Split into scheme, host, and path.
            scheme, sep, remainder = normalized.partition("://")
            host, sep, path = remainder.partition("/")
            # Host must not be a complete wildcard.
            if host == "*":
                return RiskLevel.CRITICAL
            # Acceptable paths: "", "/" or "*" (which implies /*)
            # If the path exists and is not exactly "*" or "/", flag it.
            if path and path not in ("", "*", "/"):
                return RiskLevel.HIGH
        else:
            # Invalid scheme altogether.
            return RiskLevel.HIGH

    # If all patterns pass the above checks, we consider it low risk for a few trusted domains (check trusted)
    return RiskLevel.LOW


def evaluate_web_accessible_resources(value: list[dict]) -> RiskLevel:
    """
    Evaluate the risk of web_accessible_resources based on the manifest specification.

    Each entry is expected to be a dict with the following keys:
      - "resources": a list of resource file paths.
      - "matches": a list of URL patterns allowed to access these resources.
      - "extension_ids": (optional) a list of extension IDs allowed to access these resources.

    Evaluation logic:
      1. For "matches":
         - If any pattern is "<all_urls>" or "*://*/*", mark as CRITICAL.
         - If any pattern contains any wildcard (but not full wildcard), flag as MEDIUM.
         - Otherwise, if matches are specified and are narrow, mark as LOW.
      2. For "extension_ids":
         - If any extension_id is "*" or empty, flag as HIGH (unrestricted access).
         - Otherwise, if provided and specific, mark as LOW.
      3. For "resources":
         - If any resource ends with ".js", elevate the risk to HIGH (since exposing JS is risky),
           unless already CRITICAL.
      4. net risk is the maximum risk among all entries.
    """
    net_risk = RiskLevel.NONE
    for entry in value:
        # Default risk for each entry is LOW.
        entry_risk = RiskLevel.LOW

        # Evaluate "matches"
        matches = entry.get("matches", [])
        matches_risk = RiskLevel.NONE
        if matches:
            for pattern in matches:
                p = pattern.strip().lower()
                # Overly broad patterns trigger CRITICAL risk.
                if p in {"<all_urls>", "*://*/*"}:
                    matches_risk = RiskLevel.CRITICAL
                    break
                elif "*" in p:
                    # partial wildcard, mark as MEDIUM risk
                    matches_risk = max(
                        matches_risk, RiskLevel.MEDIUM, key=lambda r: get_risk_score(r))
            if matches_risk == RiskLevel.NONE:
                matches_risk = RiskLevel.LOW
        else:
            matches_risk = RiskLevel.NONE

        # Evaluate "extension_ids"
        extension_ids = entry.get("extension_ids", [])
        ids_risk = RiskLevel.NONE
        if extension_ids:
            for ext_id in extension_ids:
                if ext_id.strip() in {"*", ""}:
                    # Unrestricted access by any extension.
                    ids_risk = RiskLevel.HIGH
                    break
            if ids_risk == RiskLevel.NONE:
                ids_risk = RiskLevel.LOW
        else:
            ids_risk = RiskLevel.NONE

        # Combine risk from matches and extension_ids: choose the higher risk.
        entry_risk = max(matches_risk, ids_risk,
                         key=lambda r: get_risk_score(r))

        # Evaluate "resources": if any resource is a JavaScript file, escalate risk to HIGH (unless CRITICAL).
        resources = entry.get("resources", [])
        for res in resources:
            if res.strip().lower().endswith(".js"):
                if entry_risk != RiskLevel.CRITICAL:
                    entry_risk = RiskLevel.HIGH

        net_risk = max(net_risk, entry_risk, key=lambda r: get_risk_score(r))

    return net_risk


def evaluate_chrome_settings_override(override: Dict[str, Any]) -> RiskLevel:
    """
    Dynamically evaluates the chrome_settings_override field by checking the domains 
    of URLs against a threat intelligence lookup

    For each setting:
      - "homepage": if the homepage's domain is flagged as malicious, return HIGH risk.
      - "search_provider": if the search_url's domain is flagged as malicious, return CRITICAL risk.
      - "startup_pages": if any startup page's domain is flagged as malicious, assign MEDIUM risk.

    The net risk is the maximum risk from these checks.
    """
    net_risk = RiskLevel.NONE

    # Evaluate homepage override.
    homepage = override.get("homepage")
    if homepage:
        domain = urlparse(homepage).netloc.split(':')[0]
        if check_domain_urlhaus(domain):
            net_risk = max(net_risk, RiskLevel.HIGH,
                           key=lambda r: get_risk_score(r))

    # Evaluate search_provider override.
    search_provider = override.get("search_provider", {})
    search_url = search_provider.get("search_url")
    if search_url:
        domain = urlparse(search_url).netloc.split(':')[0]
        if check_domain_urlhaus(domain):
            net_risk = max(net_risk, RiskLevel.CRITICAL,
                           key=lambda r: get_risk_score(r))
        # else:
        #     net_risk = max(net_risk, RiskLevel.LOW, key=lambda r: get_risk_score(r))

    # Evaluate startup_pages override.
    startup_pages = override.get("startup_pages", [])
    for page in startup_pages:
        domain = urlparse(page).netloc.split(':')[0]
        if check_domain_urlhaus(domain):
            net_risk = max(net_risk, RiskLevel.MEDIUM,
                           key=lambda r: get_risk_score(r))

    return net_risk


def evaluate_commands(commands: dict) -> RiskLevel:
    """
    Evaluate the risk of the 'commands' manifest field.

    - The default command (_execute_browser_action) is normal (LOW risk).
    - A custom command with a defined suggested key is assigned MEDIUM risk.
    - A custom command missing a suggested key is flagged as HIGH risk.

    The net risk is the maximum risk level among all commands.
    """
    net_risk = RiskLevel.NONE

    for command_name, details in commands.items():
        # For the default command, assume LOW risk.
        if command_name == "_execute_browser_action":
            command_risk = RiskLevel.LOW
        else:
            # For custom commands, if "suggested_key" exists, it's MEDIUM risk.
            # If it's missing, flag it as HIGH risk.
            if "suggested_key" in details and details["suggested_key"].get("default"):
                command_risk = RiskLevel.MEDIUM
            else:
                command_risk = RiskLevel.HIGH

        # Update net risk with the maximum risk encountered.
        net_risk = max(net_risk, command_risk, key=lambda r: get_risk_score(r))

    return net_risk


def evaluate_content_scripts(value: list[dict]) -> RiskLevel:
    """Analyze content scripts for broad access or injection risks."""
    net_risk = RiskLevel.NONE

    for script in value:
        matches = script.get("matches", [])

        # Check for overly broad match patterns
        for pattern in matches:
            if pattern == "<all_urls>" or pattern == "*://*/*":
                return RiskLevel.CRITICAL  # Very broad match pattern

            # Check if any match pattern uses wildcards
            elif "*" in pattern:
                # More specific wildcard checks can be implemented based on the pattern
                # matches common wildcard patterns
                if re.match(r"^https?://.*\..*/.*$", pattern):
                    net_risk = max(net_risk, RiskLevel.MEDIUM)

        # Check if the script has JavaScript files
        if any(res.endswith(".js") for res in script.get("js", [])):
            net_risk = max(net_risk, RiskLevel.HIGH)

    return net_risk


def evaluate_manifest_field(field: str, extension: Extension) -> RiskLevel:
    # Felt that fields like side_panel, background, devtools page would be better off
    # decided by simple risk mapping before the JS analysis section
    match field:
        case "content_security_policy":
            if extension.manifest.content_security_policy is not None:  # Error handling for empty CSP
                return evaluate_csp(extension.manifest.content_security_policy)
        case "externally_connectable":
            if extension.manifest.externally_connectable is not None:  # Error handling for empty connectable
                return evaluate_externally_connectable(extension.manifest.externally_connectable)
        case "web_accessible_resources":
            if extension.manifest.web_accessible_resources is not None:  # Error handling for empty resources
                return evaluate_web_accessible_resources(extension.manifest.web_accessible_resources)
        case "chrome_settings_override":
            if extension.manifest.chrome_settings_overrides is not None:  # Error handling for empty overrides
                return evaluate_chrome_settings_override(extension.manifest.chrome_settings_overrides)
        case "commands":
            if extension.manifest.commands is not None:  # Error handling for empty commands
                # Only flags hidden commands
                return evaluate_commands(extension.manifest.commands)
        case "content_scripts":
            if extension.manifest.content_scripts is not None:  # Error handling for empty commands
                # Only flags hidden commands
                return evaluate_content_scripts(extension.manifest.content_scripts)
        case _:
            return get_risk_level(field)


def analyze_js_risks(dynamic_sources: list[str]) -> RiskLevel:
    """
    Analyzes extracted JavaScript for risky patterns and assigns a risk level.

    Risk Patterns:
      - CRITICAL risk for patterns that directly allow arbitrary code execution:
          * eval() when used with a literal string or unclear input.
          * document.write() when used to insert external content.
          * new Function() which creates a function from a string.
      - HIGH risk for patterns that schedule code execution with string arguments:
          * setTimeout() or setInterval() where the first argument is a string literal.
          * chrome.scripting.executeScript() is flagged because it injects code into pages.
      - MEDIUM risk for generic network calls (fetch, XMLHttpRequest) that may load external content.
    """

    # Define refined dynamic patterns:
    risk_patterns = {
        # CRITICAL: Direct code execution patterns.
        RiskLevel.CRITICAL: [
            # Matches eval with any content (could be dangerous, especially if not sanitized)
            r"eval\s*\(\s*['\"].+?['\"]\s*\)",
            # Matches document.write with a literal string, which might inject external resources
            r"document\.write\s*\(\s*['\"].+?['\"]\s*\)",
            r"new\s+Function\s*\(",  # Matches new Function constructor usage
        ],
        # HIGH: Scheduling functions that accept string arguments (implying dynamic code execution)
        RiskLevel.HIGH: [
            # Matches setTimeout if the first parameter is a string literal
            r"setTimeout\s*\(\s*['\"].+?['\"]\s*,",
            # Matches setInterval if the first parameter is a string literal
            r"setInterval\s*\(\s*['\"].+?['\"]\s*,",
            # Matches chrome.scripting.executeScript usage
            r"chrome\.scripting\.executeScript\s*\(",
            # Fetch exfiltration (to malicious domains)
            r"fetch\s*\(['\"](https?://[^\s\"']+)['\"]\)",
            # Dynamic script injection
            r"document\.createElement\('script'\)\.src\s*=\s*['\"](https?://[^\s\"']+)['\"]",
        ],
        # MEDIUM: Network calls that could load external content (if unsanitized, could lead to remote code execution indirectly)
        RiskLevel.MEDIUM: [
            r"fetch\s*\(",  # Matches fetch with an external URL literal
            # Matches XMLHttpRequest usage (generic, so considered medium risk)
            r"XMLHttpRequest"
        ]
    }

    net_risk = RiskLevel.NONE

    # Iterate over each file path flagged as containing dynamic scripts.
    for file_path in dynamic_sources:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                content = (content.decode('utf-8', errors='ignore')
                           if isinstance(content, bytes) else content)
        except Exception:
            continue

        # Check content against each risk level's patterns
        for risk_level, patterns in risk_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, content) 
                if match:
                    print(f"File {file_path} triggered pattern: {pattern}")
                    print(f"Matched substring: {match.group()}")
                    net_risk = max(net_risk, risk_level, key=lambda r: get_risk_score(r))
                    break # stops after first match for the risk level but can be removed and manipulated to log all
                
    return net_risk


def get_vulnerability_info(dep_name: str) -> dict:
    """
    Fetch vulnerability information from a public API (e.g., NPM, Snyk).
    For example, using NPM's audit API or a vulnerability database.
    """
    url = f"https://registry.npmjs.org/{dep_name}/latest"  # Using NPM API as an example
    response = requests.get(url)

    if response.status_code == 200:
        return response.json()
    return {}


def analyze_dependency_risks(extension) -> list[RiskMapping]:
    """
    Analyzes dependencies for potential risks based on version checks and external databases.
    """
    dependency_risk = []

    # Fetch each dependency from the extension
    for dep, version in extension.dependencies.items():
        # Get vulnerability info for the dependency
        vuln_info = get_vulnerability_info(dep)

        if vuln_info:
            # Example: check if the version is flagged in the vulnerability database
            latest_version = packaging.version.parse(
                vuln_info.get('version', '0.0.0'))

            if packaging.version.parse(version) < latest_version:
                # Flag it as risky
                dependency_risk.append(RiskMapping(
                    permission=f"outdated_dependency: {dep}",
                    risk_level=RiskLevel.HIGH,
                    comment=f"Outdated version of {dep}; newer versions are recommended for security reasons."
                ))

    return dependency_risk


def generate_risk_mapping(name: str, risk_level: RiskLevel, comment_lookup: dict[str, str]) -> list[RiskMapping]:
    """
    Generates a list with a single RiskMapping if risk_level is not NONE.
    Returns an empty list otherwise.
    """
    if risk_level == RiskLevel.NONE:
        return []
    return [RiskMapping(
        permission=name,
        risk_level=risk_level,
        comment=comment_lookup.get(name, "")
    )]


# The risk report is entirely based on permissions, this is a possibly
# important change point based on implementation
def get_risk_report(extension: Extension) -> RiskReport:
    # Track Permission Risks
    # permissions_risk = [
    #     RiskMapping(permission=x, risk_level=get_risk_level(x), warning="new_field_added_to_make_mohammed workeasier maybe")
    #     for x in extension.permissions
    # ]
    permissions_risk = []
    for perm in extension.permissions:
        risk_level = get_risk_level(perm)
        comment = PERMISSION_RISK_COMMENTS.get(
            perm, f"No comment defined for '{perm}'")
        permissions_risk.append(RiskMapping(
            permission=perm, risk_level=risk_level, comment=comment))

    # # Track all manifest-based risks
    # manifest_risk = [
    #     RiskMapping(permission=field, risk_level=evaluate_manifest_field(field, extension, warning="hello"))
    #     for field in extension.manifest_fields
    # ]
    # For manifest fields
    manifest_risk = []
    for field in extension.manifest_fields:
        risk_level = evaluate_manifest_field(field, extension)
        manifest_risk += generate_risk_mapping(
            name=field,
            risk_level=risk_level,
            comment_lookup=RISK_COMMENTS
        )

    # Track dynamic script execution risks
    # script_sources = extension.extract_js_sources
    # dynamic_script_risk = [
    #     RiskMapping(
    #         permission="dynamic_script_execution",
    #         risk_level=analyze_js_risks(script_sources)
    #     )
    # ]
    # For dynamic script execution
    dynamic_script_risk = []
    dynamic_srcs = extension.extract_js_sources
    if dynamic_srcs:
        risk_level = analyze_js_risks(dynamic_srcs)

    dynamic_script_risk = generate_risk_mapping(
        name="dynamic_script_execution",
        risk_level=risk_level,
        comment_lookup=RISK_COMMENTS
    )

    # Dependency Analysis Risk
    # scrapped due to static analysis and time
    # # flagging known malicious urls from the manifest - test
    # malicious_urls = []
    # for url in extension.manifest_urls:
    #     domain = urlparse(url).netloc.split(':')[0]
    #     if check_domain_urlhaus(domain):
    #         malicious_urls.append(url)
    # if malicious_urls:
    #     risk_score = min(100, risk_score + get_risk_score(RiskLevel.HIGH))

    # Risk cap 100
    # Calculate the risk score from permissions, manifest, and dynamic script risks
    risk_score = min(100, sum(get_risk_score(p.risk_level)
                     for p in permissions_risk))

    # Add manifest risk levels to the score
    risk_score = min(100, risk_score + sum(get_risk_score(f.risk_level)
                     for f in manifest_risk))

    # Add dynamic script execution risk to the score
    risk_score = min(100, risk_score + sum(get_risk_score(f.risk_level)
                     for f in dynamic_script_risk))

    # Post-processing multi-field checks for manifest risks
    # Treat unsafe sandbox CSP + overly permissive externally connectable as critical risk
    if any(f.permission == "content_security_policy" and f.risk_level == RiskLevel.LOW for f in manifest_risk) and \
            any(f.permission == "externally_connectable" and f.risk_level == RiskLevel.HIGH for f in manifest_risk):
        risk_score = min(100, risk_score + get_risk_score(RiskLevel.CRITICAL))

    return RiskReport(
        name=extension.name,
        sha256=extension.sha256,
        metadata={},
        javascript_files=extension.javascript_files,
        urls=extension.urls,
        fetch_calls=[],  # Placeholder for later if needed
        risk_score=risk_score,
        permissions=permissions_risk,
        manifests=manifest_risk,
        dynamic=dynamic_script_risk,
        dynamic_sources=dynamic_srcs 
        # mal_urls=malicious_urls
        # raw_manifest=extension.manifest.json()
    )
