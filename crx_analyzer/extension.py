import os
import json
import zipfile
import shutil
import hashlib
import re

from enum import Enum
from requests import HTTPError
from . import download
from .models import ChromeManifest


class InvalidExtensionIDError(Exception):
    pass


class Browser(Enum):
    CHROME = "chrome"
    EDGE = "edge"


class Extension:
    def __init__(self, extension_id: str, browser: Browser, working_dir: str = "tmp"):
        self.extension_id = extension_id
        self.working_dir = working_dir
        self.browser = browser
        self.extension_zip_path = os.path.join(
            working_dir, f"{self.extension_id}.crx")
        self.extension_dir_path = os.path.join(
            working_dir, f"{self.extension_id}")
        self.sha256 = None  # Will be set after download
        self.urls_checkThreat = [] # added to include domains we want to scan as possible risk

        if not os.path.exists(working_dir):
            os.makedirs(working_dir)

        match self.browser:
            case Browser.CHROME:
                self.download_url = download.get_chrome_extension_url(
                    self.extension_id)
            case Browser.EDGE:
                self.download_url = download.get_edge_extension_url(
                    self.extension_id)
            case _:
                raise ValueError(f"Invalid browser: {self.browser}")
        try:
            self.__download_extension()
        except HTTPError as e:
            match e.response.status_code:
                case 404:
                    raise InvalidExtensionIDError(
                        f"403: Extension ID {self.extension_id} not found. Requested URL: {e.request.url}"
                    )

                case _:
                    raise e

        self.sha256 = hashlib.sha256(
            open(self.extension_zip_path, "rb").read()
        ).hexdigest()
        self.__unzip_extension()

        self.manifest = self.__get_manifest()

    def __unzip_extension(self) -> None:
        with zipfile.ZipFile(self.extension_zip_path, "r") as zip_ref:
            zip_ref.extractall(self.extension_dir_path)

    def __download_extension(self) -> None:
        download.download_extension(self.download_url, self.extension_zip_path)

    def __get_manifest(self) -> ChromeManifest:
        manifest_path = os.path.join(self.extension_dir_path, "manifest.json")
        with open(manifest_path, "r") as manifest_file:
            manifest_data = json.load(manifest_file)

        return ChromeManifest(**manifest_data)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        os.remove(self.extension_zip_path)
        shutil.rmtree(self.extension_dir_path)

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def version(self) -> str:
        return self.manifest.version

    @property
    def manifest_version(self) -> int:
        return self.manifest.manifest_version

    @property
    def author(self) -> str:
        return self.manifest.author

    @property
    def homepage_url(self) -> str:
        return self.manifest.homepage_url

    @property
    def permissions(self) -> list[str]:
        match self.manifest_version:
            case 2:
                permissions = self.manifest.permissions or []
                optional = self.manifest.optional_permissions or []
                return permissions + optional
            case 3:
                permissions = self.manifest.permissions or []
                optional = self.manifest.optional_permissions or []
                host = self.manifest.host_permissions or []
                optional_host = self.manifest.optional_host_permissions or []
                return permissions + optional + host + optional_host

    @property
    def javascript_files(self) -> list[str]:
        js_files = []
        for root, _, files in os.walk(self.extension_dir_path):
            for file in files:
                if file.endswith(".js"):
                    js_files.append(os.path.join(root, file))
        return js_files
    
    @property
    def html_files(self) -> list[str]:
        html_files = []
        for root, _, files in os.walk(self.extension_dir_path):
            for file in files:
                if file.endswith(".html"):
                    html_files.append(os.path.join(root, file))
        return html_files
    
    @property
    def extract_js_sources(self) -> dict[str, list[str]]:
        """
        Extracts JavaScript code from all sources within the extension:
        - Standalone .js files
        - Inline <script> tags in .html files
        - Dynamic execution patterns from scripts
        """
        script_sources = {
            "js_files": [],
            "inline_scripts": [],
            "dynamic_scripts": []
        }
        # Define dynamic patterns
        dynamic_patterns = [
            r"eval\s*\(",                                       # Detect eval()
            r"document\.write\s*\(",                            # Detect document.write()
            r"new Function\s*\(",                               # Detect new Function()
            r"setTimeout\s*\(.*?\)",                            # Detect setTimeout() usage
            r"setInterval\s*\(.*?\)",                           # Detect setInterval() usage
            r"chrome\.scripting\.executeScript\s*\(",           # Detect chrome.scripting.executeScript()
            r"fetch\s*\(",                                      # Detect regular fetch usage
            r"fetch\s*\(\s*['\"](https?://[^\s'\"<>]+)['\"]",   # Detect fetch() with external URL literal
            r"XMLHttpRequest"                                   # Detect XMLHttpRequest usage
        ]
        combined_dynamic_pattern = re.compile("|".join(dynamic_patterns), re.IGNORECASE)

        # Extract JavaScript and HTML content
        for root, _, files in os.walk(self.extension_dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Extract from .js files
                if file.endswith(".js"):
                    script_sources["js_files"].append(file_path)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        script_content = f.read()
                        if combined_dynamic_pattern.search(script_content):
                            script_sources["dynamic_scripts"].append(file_path)
                
                # Extract inline scripts from .html files
                elif file.endswith(".html"):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        html_content = f.read()
                        inline_scripts = re.findall(r"<script.*?>(.*?)</script>", html_content, re.DOTALL)
                        script_sources["inline_scripts"].extend(inline_scripts)
                        # Check inline scripts for dynamic patterns
                        for inline_script in inline_scripts:
                            if combined_dynamic_pattern.search(inline_script):
                                script_sources["dynamic_scripts"].append(inline_script)

        return script_sources
    
    @property
    def urls(self) -> list[str]:
        urls = set()
        patterns = [
            r'file://[^\s<>"\']+',
            r'https?://[^\s<>"\']+',
            r'http?://[^\s<>"\']+',
        ]

        for js_file in self.javascript_files:
            with open(js_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for pattern in patterns:
                    found_urls = re.findall(pattern, content)
                    urls.update(found_urls)

        return list(urls)

    @property
    def fetch_calls(self) -> list[str]:
        fetch_calls = set()
        fetch_pattern = r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]'

        for js_file in self.javascript_files:
            with open(js_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                found_fetch_calls = re.findall(fetch_pattern, content)
                fetch_calls.update(found_fetch_calls)

        return list(fetch_calls)
    
    
    @property
    def manifest_fields(self) -> list[str]: 
        return list(self.manifest.model_dump(exclude_unset=True).keys())
    
    @property
    def manifest_urls(self) -> list[str]:
        def extract(obj):
            urls = []
            if isinstance(obj, dict):
                for value in obj.values():
                    urls.extend(extract(value))  
            elif isinstance(obj, list):
                for item in obj:
                    urls.extend(extract(item)) 
            elif isinstance(obj, str):
                urls.extend(re.findall(r'https?://[^\s<>"\']+', obj))  # Find URLs
            return urls

        return extract(self.manifest)
    
  
