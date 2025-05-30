from flask import Flask, render_template, request
import json
from crx_analyzer.cli import analyze
import re
import server.llm as llm
from pprint import pprint
app = Flask(__name__, static_folder='static', template_folder='templates')


def check_extension_name(ext_name, ext_url):
    """
    Check and fix extension name if missing by extracting it from the extension URL.

    Args:
        ext_name (str): The extension name.
        ext_url (str): The extension URL.

    Returns:
        str: The fixed extension name.
    """
    if "MSG" in ext_name:
        pattern = r"https?://chromewebstore\.google\.com/detail/([^/]+)/"
        match = re.search(pattern, ext_url)
        if match:
            ext_name = match.group(1)
    return ext_name.upper()


def get_explanations(_permissions_list):
    """
    Retrieves explanations for a list of permissions using a language model.

    Args:
        _permissions_list (list): A list of permissions to get explanations for.

    Returns:
        list: A list containing the explanations for the provided permissions.
    """

    llm_model = llm.setup_model()
    results = llm.handle_explanations(
        llm_model, _permissions_list, len(_permissions_list))
    return results


def extract_id(url):
    """
    Extract the Chrome extension ID from a given Chrome Web Store URL.

    Args:
        url (str): The URL of the Chrome extension.

    Returns:
        str or None: The 32-character extension ID if found, else None.
    """
    pattern = r"https?://chromewebstore\.google\.com/detail/[^/]+/([a-p]{32})"
    match = re.search(pattern, url)
    if match:
        extension_id = match.group(1)
        print(f"[+] Found Extension id: {extension_id}")
        return extension_id
    else:
        return None


def get_analysis_results(ext_id):
    """
    Analyze the Chrome extension with crx-analyzer using its extension ID.

    Args:
        ext_id (str): The 32-character extension ID.

    Returns:
        str: Analysis results in the specified format, or "Invalid URL" if ext_id is None.
    """
    max_urls = 10       # Max number of URLs to display
    max_files = 10      # Max number of JS files to display
    output_format = "pretty"  # Output format ("pretty" or "json")
    permissions_flag = False  # Display only permissions and metadata tables

    if ext_id is None:
        return "Invalid URL"
    str_data = analyze(id=ext_id, browser="chrome", output=output_format,
                       max_files=max_files, max_urls=max_urls, permissions=permissions_flag)
    return str_data


@app.route('/')
def index():
    """
    Render the main index page.

    Returns:
        str: Rendered HTML for the index page.
    """
    return render_template('index.html')


@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    """
    Process the Chrome extension URL submitted via POST, perform analysis, and render results.

    Returns:
        str: Rendered HTML for the index page with analysis data.
    """
    extension_url = request.form['ext_url']
    analysis_results = get_analysis_results(extract_id(extension_url))

    if analysis_results != "Invalid URL":
        try:
            json_data = json.loads(analysis_results)
            with open('report.json', 'w') as f:
                json.dump(json_data, f)
        except json.JSONDecodeError:
            return render_template('index.html', analysis_data={})
    else:
        print("[-] Invalid URL")
        return render_template('index.html', analysis_data={})

    if isinstance(analysis_results, str):
        try:
            analysis_results = json.loads(analysis_results)
            analysis_results["name"] = check_extension_name(
                analysis_results["name"], extension_url)
        except json.JSONDecodeError:
            print("[-] Error while analyzing this extension")
            return render_template('index.html', analysis_data={})

    permissions_list = analysis_results.get("permissions", [])
    if permissions_list:
        explanations = get_explanations(permissions_list)
        analysis_results["explanations"] = explanations
    else:
        analysis_results["message"] = "No permissions found in the extension."
    pprint(analysis_results)
    return render_template('index.html', analysis_data=analysis_results)


if __name__ == '__main__':
    app.run(debug=True)
