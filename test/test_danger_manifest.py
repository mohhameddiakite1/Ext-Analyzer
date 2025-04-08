import json, re
from unittest.mock import Mock, mock_open
import pytest
import os
import shutil
from pathlib import Path
from crx_analyzer.extension import Extension, Browser
from crx_analyzer.risk import (
    evaluate_externally_connectable,
    evaluate_csp,
    evaluate_manifest_field,
    evaluate_web_accessible_resources,
    evaluate_chrome_settings_override,
    evaluate_commands,
    analyze_js_risks,
    generate_risk_mapping,
    get_risk_report,
)
from crx_analyzer.models import (
    ChromeManifest,
    ExternallyConnectable,
    ChromePermission,
    RiskLevel,
    RiskMapping,
)

test_cases = [
    (
        "test/test_manifests/manifest_dangerous.json",
        {
            "manifest_version": 3,
            "name": "Malicious Extension",
            "version": "1.0",
            "description": "This extension does suspicious things.",
            "permissions": [
                "tabs",
                "storage",
                "proxy",
                "clipboardRead",
                "cookies",
                "webRequest",
                "debugger"
            ],
            "host_permissions": [
                "<all_urls>",
                "file:///*"
            ],
            "background": {
                "service_worker": "background.js"
            },
            "content_scripts": [
                {
                    "matches": ["https://*/*", "http://*/*"],
                    "js": ["https://shady.cdn.com/tracker.js", "content.js"]
                }
            ],
            "chrome_url_overrides": {
                
            },
            "externally_connectable": {
                "matches": ["*://*.evil-site.com/*"]
            },
            "web_accessible_resources": [
                {
                    "resources": ["injected_script.js"],
                    "matches": ["*://*/"]
                }
            ]
        },
  
    ),
]

def fake_sha256(data):
    class FakeHash:
        def hexdigest(self):
            return "f4396645d06777cb879406c3226cb69b60fc923baff1868fb5db4588ef0e07e6"
    return FakeHash()

mocked_file = mock_open(read_data=b"mocked file content")
real_open = open  # preserve the original open

def smart_open(file, mode='r', *args, **kwargs):
    # Only return mocked content for binary reads — i.e., where real file doesn't exist
    if 'b' in mode and 'r' in mode:
        try:
            return real_open(file, mode, *args, **kwargs)
        except FileNotFoundError:
            return mocked_file()
    return real_open(file, mode, *args, **kwargs)    


@pytest.mark.parametrize("manifest_file,expected", test_cases)
def test_manifest(monkeypatch, manifest_file, expected):
    
    """Test risk report generation for a "known" hazardous extension."""
    # Path to the unpacked extension
    extension_path = Path(__file__).parent.parent / "hazardous_test_extension"
    manifest_path = Path(__file__).parent.parent / "hazardous_test_extension" / "manifest.json"
    manifest_data = json.load(open(manifest_path))
    manifest = ChromeManifest(**manifest_data)
    
    monkeypatch.setattr(
        "crx_analyzer.download.download_extension", 
        lambda self, some_arg: None  # Directly return the mock object
    )
    monkeypatch.setattr(
        "crx_analyzer.extension.Extension._Extension__unzip_extension", 
        lambda self: None  # Directly return the mock object
    )
    monkeypatch.setattr("crx_analyzer.extension.hashlib.sha256", fake_sha256)
    monkeypatch.setattr(
        "crx_analyzer.extension.Extension._Extension__get_manifest", 
        lambda self: manifest  # Directly return the mock object
    )
    # Patch open to return mock file data
    monkeypatch.setattr("builtins.open", smart_open)
    
    
    ## aim to override the autodownload
    extension_id = "hazardous"
    e = Extension(extension_id, Browser.EDGE)
    monkeypatch.setattr(e, "extension_dir_path", extension_path)
    
    
    
    ## check patching hashlib worked
    assert e.sha256 == "f4396645d06777cb879406c3226cb69b60fc923baff1868fb5db4588ef0e07e6"
    
    assert e.manifest == manifest
       
    # script_sources = e.extract_js_sources
    # print(script_sources)
    # if script_sources:
    #     risk_level = analyze_js_risks(script_sources)
    # print(risk_level)
    
    report = get_risk_report(e)
    print(report)
    

@pytest.mark.parametrize("csp_value, expected_risk", [
    # Safe cases (NONE risk)
    ({}, RiskLevel.NONE),  # No CSP specified
    ("default-src 'self'; script-src 'self'", RiskLevel.NONE),  # Strict CSP
    
    # CRITICAL risk cases
    ("default-src *", RiskLevel.CRITICAL),  # Allows all domains for all resources
    ("script-src *", RiskLevel.CRITICAL),  # Allows scripts from all domains
    ({"extension_pages": "default-src *"}, RiskLevel.CRITICAL),  # Dict input version

    # HIGH risk cases
    ("script-src 'unsafe-inline'", RiskLevel.HIGH),  # Allows inline scripts (XSS risk)
    ("script-src 'unsafe-eval'", RiskLevel.HIGH),  # Allows eval() (XSS risk)
    ({"extension_pages": "script-src 'unsafe-eval'"}, RiskLevel.HIGH),  # Dict input version

    # LOW risk cases (sandboxed issues)
    ({"sandbox": "script-src 'unsafe-eval'"}, RiskLevel.LOW),  # Sandboxed eval (contained but weak)
    ({"sandbox": "default-src *"}, RiskLevel.LOW),  # Sandboxed allows loading from anywhere

    # Mixed case handling (should be case-insensitive)
    ("DeFaUlT-SrC *", RiskLevel.CRITICAL),  
    ({"extension_pages": "ScRiPt-SrC 'UnSaFe-InLiNe'"}, RiskLevel.HIGH),  
])
def test_evaluate_csp(csp_value, expected_risk):
    assert evaluate_csp(csp_value) == expected_risk
 
    

@pytest.mark.parametrize("externally_connectable, expected_risk", [
    # Valid patterns (Lower Risk)
    (ExternallyConnectable(matches=["https://example.com/*"]), RiskLevel.LOW),
    (ExternallyConnectable(matches=["http://*.example.org/*"]), RiskLevel.LOW),
    
    # Invalid patterns (HIGH Risk due to misconfiguration)
    (ExternallyConnectable(matches=["*://example.com/one/"]), RiskLevel.HIGH),
    (ExternallyConnectable(matches=["http://*/"]), RiskLevel.CRITICAL),
    
    # Overly permissive patterns (HIGH Risk)
    (ExternallyConnectable(matches=["<all_urls>"]), RiskLevel.CRITICAL),
    (ExternallyConnectable(matches=["*://*/*"]), RiskLevel.CRITICAL),
    (ExternallyConnectable(matches=["http://*/*"]), RiskLevel.CRITICAL),
    (ExternallyConnectable(matches=["https://*/*"]), RiskLevel.CRITICAL),
    
    # Safe case: No externally connectable definition
    (ExternallyConnectable(), RiskLevel.NONE),
])
def test_evaluate_externally_connectable(externally_connectable, expected_risk):
    assert evaluate_externally_connectable(externally_connectable) == expected_risk


@pytest.mark.parametrize("entry_list, expected_risk", [
    # Case 1: Narrow match with non-JS resource → LOW risk.
    (
        [{"matches": ["https://example.com/"], "resources": ["style.css"]}],
        RiskLevel.LOW
    ),
    # Case 2: Pattern with wildcard in host (e.g., http://*.example.org/*) → MEDIUM risk.
    (
        [{"matches": ["http://*.example.org/*"], "resources": ["image.png"]}],
        RiskLevel.MEDIUM
    ),
    # Case 3: Overly broad pattern using <all_urls> → CRITICAL risk.
    (
        [{"matches": ["<all_urls>"], "resources": ["script.js"]}],
        RiskLevel.CRITICAL
    ),
    # Case 4: Valid match but exposing a JS file → Elevate to HIGH risk.
    (
        [{"matches": ["https://example.com/*"], "resources": ["script.js"]}],
        RiskLevel.HIGH
    ),
    # Case 5: Using extension_ids with a wildcard → HIGH risk.
    (
        [{"extension_ids": ["*"], "resources": ["style.css"]}],
        RiskLevel.HIGH
    ),
    # Case 6: Using a legitimate extension_id → LOW risk.
    (
        [{"extension_ids": ["abcdefgh12345678"], "resources": ["style.css"]}],
        RiskLevel.LOW
    ),
    # Case 7: Multiple entries; overall risk should be the maximum (CRITICAL).
    (
        [
            {"matches": ["https://example.com/"], "resources": ["style.css"]},
            {"matches": ["*://*/*"], "resources": ["script.js"]}
        ],
        RiskLevel.CRITICAL
    ),
])
def test_evaluate_web_accessible_resources(entry_list, expected_risk):
    risk_level = evaluate_web_accessible_resources(entry_list)
    assert risk_level == expected_risk
    

# --- Helper: Fake URLhaus Lookup ---
def fake_check_domain_urlhaus(domain: str) -> bool:
    # For testing, flag only "evil.com" as malicious.
    return domain == "evil.com"

@pytest.fixture(autouse=True)
def patch_urlhaus(monkeypatch):
    # Patch the URLhaus lookup function in your module.
    monkeypatch.setattr("crx_analyzer.risk.check_domain_urlhaus", fake_check_domain_urlhaus)

# --- Pytest for evaluate_chrome_settings_override ---
@pytest.mark.parametrize("override, expected_risk", [
    ({"homepage": "https://trusted.com/home"}, RiskLevel.NONE),
    ({"homepage": "https://evil.com/home"}, RiskLevel.HIGH),
    ({"search_provider": {"search_url": "https://trusted.com/search"}}, RiskLevel.NONE),
    ({"search_provider": {"search_url": "https://evil.com/search"}}, RiskLevel.CRITICAL),
    ({"startup_pages": ["https://evil.com/start"]}, RiskLevel.MEDIUM),
    (
        {
            "homepage": "https://trusted.com/home",
            "search_provider": {"search_url": "https://evil.com/search"},
        },
        RiskLevel.CRITICAL
    ),
])
def test_evaluate_chrome_settings_override(override, expected_risk):
    risk = evaluate_chrome_settings_override(override)
    assert risk == expected_risk

# --- Pytest for evaluate_commands ---
@pytest.mark.parametrize("commands_input, expected", [
    ({"_execute_browser_action": {"suggested_key": {"default": "Ctrl+Shift+U"}}}, RiskLevel.LOW),
    ({"stealth_action": {"suggested_key": {"default": "Ctrl+Shift+X"}}}, RiskLevel.MEDIUM),
    ({"hidden_action": {}}, RiskLevel.HIGH),
    (
        {
            "_execute_browser_action": {"suggested_key": {"default": "Ctrl+Shift+U"}},
            "hidden_action": {}
        },
        RiskLevel.HIGH
    ),
])
def test_evaluate_commands(commands_input, expected):
    risk = evaluate_commands(commands_input)
    assert risk == expected    
    
    
def test_dynamic_script_execution():
    sources = {"js_files": ["eval('malicious code')"]}
    risks = analyze_js_risks(sources)
    assert risks == RiskLevel.CRITICAL
    
    sources = {"inline_scripts": ["document.write('<img src=steal>')"]}
    risks = analyze_js_risks(sources)
    assert risks == RiskLevel.CRITICAL

    sources = {"js_files": ["fetch('https://evil.com')"]}
    risks = analyze_js_risks(sources)
    assert risks == RiskLevel.HIGH
    
    sources = {"js_files": ["console.log('Hello')"]}
    risks = analyze_js_risks(sources)
    assert risks == RiskLevel.NONE

    sources = {"js_files": ["eval('x')\ndocument.write('bad')\nfetch('http://a')"]}
    risks = analyze_js_risks(sources)
    assert risks == RiskLevel.CRITICAL