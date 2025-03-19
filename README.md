# Ext-Analyzer

## Summary

**Ext-Analyzer** is an open-source project aimed at enhancing the security evaluation of browser extensions. Building on the foundation of [crx-analyzer](https://github.com/rileydakota/crx-analyzer), our goal is to develop a web-based platform that improves the existing static analysis, provides detailed risk scoring, and offers customizable report generation. This tool is designed to help security professionals assess and secure browser extensions more effectively.

## Prerequisites

- [Python 3.10.7](https://www.python.org/downloads/release/python-3107/)
- [Google Chrome](https://www.google.com/chrome/)
- [Ollama 0.6.1](https://github.com/ollama/ollama/releases/tag/v0.6.1)

## Setup Guide

### 1. Clone or Download the Repository

**Using Git (Cloning):**

1. Open your terminal (or command prompt on Windows).
2. Run the command:
    ```bash
    git clone <repository-url>
    ```
   Replace `<repository-url>` with the actual URL of the repository.
3. Navigate to the project folder:
    ```bash
    cd /path/to/your/project-directory
    ```

**Without Git (Downloading):**

1. Download the ZIP file from the repository's GitHub page.
2. Extract the ZIP file.
3. Open your terminal and navigate to the extracted folder:
    ```bash
    cd /path/to/your/project-directory
    ```

### 2. Install Python 3.10.7

**For Windows:**

1. Go to the [Python 3.10.7 download page](https://www.python.org/downloads/release/python-3107/).
2. Download the "Windows x86-64 executable installer."
3. Run the installer and **check "Add Python to PATH"** before clicking "Install Now."

**For macOS/Linux:**

- **macOS:** Use [Homebrew](https://brew.sh/):
    ```bash
    brew install python@3.10
    ```
- **Linux (Ubuntu):**
    ```bash
    sudo apt update
    sudo apt install python3.10
    ```

Verify installation by running:

```bash
python --version
```

### 3. Download Ollama 0.6.1

1. Visit the [Ollama releases page](https://github.com/ollama/ollama/releases/tag/v0.6.1).
2. Download the appropriate installer for your operating system.
   - For macOS, download the macOS installer.
   - For Windows, download the Windows executable.
   - For Linux, follow the provided instructions in the release notes.
3. Follow the installation instructions provided on the release page.
4. Verify the installation by running:
    ```bash
    ollama --version
    ```
   You should see output indicating version 0.6.1.

### 4. Set Up the Virtual Environment

1. In your project directory, create a virtual environment:
    ```bash
    python -m venv venv
    ```
2. Activate the virtual environment:

   - **Windows:**
        ```bash
        venv\Scripts\activate
        ```
   - **macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```

### 5. Install Dependencies

With the virtual environment activated, install the required packages:

```bash
pip install -r requirements.txt
```

### 6. Start the Program

1. Ensure your virtual environment is activated and you are in the project’s root directory.
2. Run the program:
    ```bash
    python -m server.server
    ```
3. Open your browser and navigate to the web interface (localhost).
4. Visit the Chrome Web Store, copy an extension URL (e.g., [Boxel Rebound](https://chromewebstore.google.com/detail/boxel-rebound/iginnfkhmmfhlkagcmpgofnjhanpmklb)), paste it into the search field, and click **Analyze**.
