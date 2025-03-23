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
# import requests
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
        "commands",  # Only if hidden commands exist
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
        "chrome_settings_override",  # Can hijack homepage/search
        "background",  # Just flags persistent execution, JS analysis checks real risk
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
        "web_accessible_resources",  # Allows injection into other websites
        "externally_connectable",   # Can communicate with external sites
        "content_security_policy",  # If weak CSP settings exist
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
        extension_policies = csp_value.get("extension_pages","").lower()
        sandbox_policies = csp_value.get("sandbox","").lower()
    elif isinstance(csp_value, str):
        extension_policies = csp_value.lower()
        sandbox_policies = ""
    else:
        return RiskLevel.NONE # Invalud csp format, assume no risk
        
    # checking extension_pages csp as  it affects main extension security        
    if "default-src *" in extension_policies or "script-src *" in extension_policies: # allows scripts from all domain's
        return RiskLevel.CRITICAL
    if "'unsafe-eval'" in extension_policies or "'unsafe-inline'" in extension_policies: # allows inline scripts or eval() xss
        return RiskLevel.HIGH
    # check csp sandbox (less impactful)
    if "'unsafe-eval'" in sandbox_policies or "'unsafe-inline'" in sandbox_policies:
        return RiskLevel.LOW #sandboxed eval is not ideal but not highly dangerous
    if "default-src *" in sandbox_policies or "script-src *" in sandbox_policies:
        return RiskLevel.LOW #sandboxed loading scripts from anywhere is weak but contained
    
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
        if normalized in {"<all_urls>","*://*/*"}:
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
                    matches_risk = max(matches_risk, RiskLevel.MEDIUM, key=lambda r: get_risk_score(r))
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
                    ids_risk = RiskLevel.HIGH  # Unrestricted access by any extension.
                    break
            if ids_risk == RiskLevel.NONE:
                ids_risk = RiskLevel.LOW
        else:
            ids_risk = RiskLevel.NONE

        # Combine risk from matches and extension_ids: choose the higher risk.
        entry_risk = max(matches_risk, ids_risk, key=lambda r: get_risk_score(r))
        
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
            net_risk = max(net_risk, RiskLevel.HIGH, key=lambda r: get_risk_score(r))

    # Evaluate search_provider override.
    search_provider = override.get("search_provider", {})
    search_url = search_provider.get("search_url")
    if search_url:
        domain = urlparse(search_url).netloc.split(':')[0]
        if check_domain_urlhaus(domain):
            net_risk = max(net_risk, RiskLevel.CRITICAL, key=lambda r: get_risk_score(r))
        # else:
        #     net_risk = max(net_risk, RiskLevel.LOW, key=lambda r: get_risk_score(r))    

    # Evaluate startup_pages override.
    startup_pages = override.get("startup_pages", [])
    for page in startup_pages:
        domain = urlparse(page).netloc.split(':')[0]
        if check_domain_urlhaus(domain):
            net_risk = max(net_risk, RiskLevel.MEDIUM, key=lambda r: get_risk_score(r))
    
            

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
                if re.match(r"^https?://.*\..*/.*$", pattern):  # matches common wildcard patterns
                    net_risk = max(net_risk, RiskLevel.MEDIUM)
        
        # Check if the script has JavaScript files
        if any(res.endswith(".js") for res in script.get("js", [])):
            net_risk = max(net_risk, RiskLevel.HIGH)
    
    return net_risk
    
def evaluate_manifest_field(field: str, extension: Extension) -> RiskLevel:
    ## Felt that fields like side_panel, background, devtools page would be better off
    ## decided by simple risk mapping before the JS analysis section
    match field:
        case "content_security_policy":
            return evaluate_csp(extension.manifest.content_security_policy)
        case "externally_connectable":
            return evaluate_externally_connectable(extension.manifest.externally_connectable)
        case "web_accessible_resources":
            return evaluate_web_accessible_resources(extension.manifest.web_accessible_resources)
        case "chrome_settings_override":
            return evaluate_chrome_settings_override(extension.manifest.chrome_settings_overrides)
        case "commands":
            return evaluate_commands(extension.manifest.commands)  # Only flags hidden commands
        case "content_scripts":
            return evaluate_content_scripts(extension.manifest.commands)  # Only flags hidden commands
        case _:
            return get_risk_level()
        
def analyze_js_risks(script_sources: dict[str, list[str]]) -> RiskLevel:
    """
    Analyzes extracted JavaScript for risky patterns and assigns a risk level.
    """
    risk_patterns = {
        RiskLevel.CRITICAL: [
            r"eval\s*\(",  # Malicious eval usage
            r"document\.write\s*\(",  # Malicious document.write
            r"new Function\s*\(",  # Malicious function creation
            r"chrome\.scripting\.executeScript\s*\(",  # Chrome extension script execution
        ],
        RiskLevel.HIGH: [
            r"setTimeout\s*\(.*?\)",  # Timed execution (can be dangerous)
            r"setInterval\s*\(.*?\)",  # Repeated timed execution
            r"fetch\s*\(['\"](https?://[^\s\"']+)['\"]\)",  # Fetch exfiltration (to malicious domains)
            # r"XMLHttpRequest\s*\(["' ](https?://[^\s\"']+)['\"]",  # XMLHttpRequest exfiltration
            r"document\.createElement\('script'\)\.src\s*=\s*['\"](https?://[^\s\"']+)['\"]",  # Dynamic script injection
        ],
        RiskLevel.MEDIUM: [
            r"fetch\s*\(",  # Fetching from potentially untrusted sources
            r"XMLHttpRequest",  # Risky XMLHttpRequest usage
        ]
    }
    
    net_risk = RiskLevel.NONE
    
    for source_type, scripts in script_sources.items():
        for script in scripts:
            for risk_level, patterns in risk_patterns.items():
                if any(re.search(pattern, script) for pattern in patterns):
                    net_risk = max(net_risk, risk_level, key=lambda r: get_risk_score(r))
    
    return net_risk
    
## The risk report is entirely based on permissions, this is a possibly 
## important change point based on implementation
def get_risk_report(extension: Extension) -> RiskReport:
    # Track Permission Risks
    permissions_risk = [
        RiskMapping(permission=x, risk_level=get_risk_level(x), warning="new_field_added_to_make_mohammed workeasier maybe")
        for x in extension.permissions
    ]
    
    # Track all manifest-based risks
    manifest_risk = [
        RiskMapping(permission=field, risk_level=evaluate_manifest_field(field, extension, warning="hello"))
        for field in extension.manifest_fields
    ]
    
    # Track dynamic script execution risks
    dynamic_script_risk = []
    # for js_file in extension.javascript_files:
    #     with open(js_file, "r", encoding="utf-8", errors="ignore") as f:
    #         content = f.read()
    #         if "eval(" in content or "document.write(" in content:
    #             dynamic_script_risk.append(PermissionRiskMapping(
    #                 permission="dynamic_script_execution",
    #                 risk_level=RiskLevel.HIGH
    #             ))
    #         if "setTimeout(" in content or "fetch(" in content:
    #             dynamic_script_risk.append(PermissionRiskMapping(
    #                 permission="remote_script_loading",
    #                 risk_level=RiskLevel.MEDIUM
    #             ))
    script_sources = extension.extract_js_sources
    
    

    # Dependency Analysis Risk
    # dependency_risk = []
    # for dep, version in extension.dependencies.items():
    #     if dep == "jquery" and version < "3.0.0":
    #         dependency_risk.append(PermissionRiskMapping(
    #             permission=f"outdated_dependency: {dep}",
    #             risk_level=RiskLevel.HIGH
    #         ))
    
    #Risk cap 100
    risk_score = min(100, sum(get_risk_score(p.risk_level)
                     for p in permissions_risk))
    
    # post-processing multi-field check
    # done based on fields processing only so far
    # for now, treating the unsafe sandbox csp + overly permisive externally connectable as critical risk 
    if any(f.permission == "content_security_policy" and f.risk_level == RiskLevel.LOW for f in manifest_risk) and \
        any(f.permission == "externally_connectable" and f.risk_level == RiskLevel.HIGH for f in manifest_risk):
            risk_score = min(100, risk_score + get_risk_score(RiskLevel.CRITICAL))
    
    # flagging known malicious urls from the manifest - test
    malicious_urls = []
    for url in extension.manifest_urls:  
        domain = urlparse(url).netloc.split(':')[0]
        if check_domain_urlhaus(domain): 
            malicious_urls.append(url)
    
    if malicious_urls:
        risk_score = min(100, risk_score + get_risk_score(RiskLevel.HIGH))
    
    return RiskReport(
        name=extension.name,
        sha256=extension.sha256,
        metadata={},
        javascript_files=extension.javascript_files,
        urls=extension.urls,
        fetch_calls=[],
        risk_score=risk_score,
        permissions=permissions_risk,
        mal_urls=malicious_urls
        # raw_manifest=extension.manifest.json()
    )
