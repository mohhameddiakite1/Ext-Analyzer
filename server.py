from flask import Flask, render_template, request
from pathlib import Path
import sys
import json
from crx_analyzer.cli import analyze
import re


app = Flask(__name__)


def extract_id(url):
    pattern = r"https?://chromewebstore\.google\.com/detail/[^/]+/([a-p]{32})"
    match = re.search(pattern, url)
    if match:
        extension_id = match.group(1)
        print(f"[+] Found Extension id: {extension_id}")
        return (extension_id)
    else:
        return None


def get_analysis_results(ext_id):
    max_urls = 10  # Max num of urls to display
    max_files = 10  # Max num of js files to display
    output_format = "pretty"  # Output format ("pretty" or "json")
    permissions_flag = False  # Display only permissions and metadata tables

    if ext_id is None:
        return "Invalid URL"
    str_data = analyze(id=ext_id, browser="chrome", output=output_format,
                       max_files=max_files, max_urls=max_urls, permissions=permissions_flag)
    return str_data


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_url():
    extension_url = request.form['ext_url']
    analysis_results = get_analysis_results(extract_id(extension_url))

    if analysis_results != "Invalid URL":
        # To facilitate data extraction
        json_data = json.loads(analysis_results)

    return render_template('index.html', analysis_dara=analysis_results)


if __name__ == '__main__':
    app.run(debug=True)
