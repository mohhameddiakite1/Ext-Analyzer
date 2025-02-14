from .cli import analyze
import re


def extract_id(url):
    pattern = r"https?://chromewebstore\.google\.com/detail/[^/]+/([a-p]{32})"
    match = re.search(pattern, url)
    if match:
        extension_id = match.group(1)
        print(f"[+] Found Extension id: {extension_id}")
        return (extension_id)


def main():
    ext_id = extract_id(input("Enter the url: "))
    max_urls = 10  # Max num of urls to display
    max_files = 10  # Max num of js files to display
    permissions_flag = False  # Display only permissions and metadata tables
    analyze(id=ext_id, browser="chrome", output="pretty",
            max_files=max_files, max_urls=max_urls, permissions=permissions_flag)


if __name__ == "__main__":
    main()
