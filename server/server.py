from flask import Flask, render_template, request
import sys
import json
from crx_analyzer.cli import analyze
import re
from pprint import pprint

app = Flask(__name__, static_folder='static', template_folder='templates')


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
    Analyze the Chrome extension using its extension ID.

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

    Extracts the extension ID from the URL, retrieves the analysis data, writes a JSON report
    if possible, and returns the rendered index page with analysis results.

    Returns:
        str: Rendered HTML for the index page with analysis data.
    """
    extension_url = request.form['ext_url']
    analysis_results = get_analysis_results(extract_id(extension_url))

    if analysis_results != "Invalid URL":
    #     try:
    #         json_data = json.loads(analysis_results)
    #         with open('report.json', 'w') as f:
    #             json.dump(json_data, f, indent=4)
    #     except json.JSONDecodeError:
    #         return render_template('index.html', analysis_data={})

    # if isinstance(analysis_results, str):
    #     try:
    #         analysis_results = json.loads(analysis_results)
    #     except json.JSONDecodeError:
    #         analysis_results = {}
    # print(analysis_results)
    # return render_template('index.html', analysis_data=analysis_results)

        try:
            # Try parsing JSON once
            analysis_results = json.loads(analysis_results) if isinstance(analysis_results, str) else analysis_results
            with open('report.json', 'w') as f:
                json.dump(analysis_results, f, indent=4)  # Pretty-print JSON
        except json.JSONDecodeError:
            analysis_results = {}  # Default to empty dict if parsing fails

        pprint(analysis_results)
        return render_template('index.html', analysis_data=analysis_results)


if __name__ == '__main__':
    app.run(debug=True)
