# 🕵️ Grabipy: Threat Intelligence & IOC Enrichment Tool
## Created by Blu3J4x

Grabipy is a robust and user-friendly Python script for threat intelligence. It automatically scans files and folders to extract Indicators of Compromise (IOCs), including IPs, hashes (MD5, SHA1, SHA256), domains, URLs, and email addresses, and enriches them using external APIs.

<img width="600" height="458" alt="image" src="https://github.com/user-attachments/assets/4e884204-100f-4ba0-b287-25f4512f5976" />

***
---
## Core Functionality

Grabipy is a comprehensive threat intelligence tool designed to automate the discovery and analysis of Indicators of Compromise (IOCs) from a wide array of sources.

* **Multi-Source IOC Extraction** 🕵️‍♂️
    * Scans individual files or entire folders to recursively find and parse supported documents.
    * Extracts a wide range of IOC types: **IP addresses** (IPv4 & IPv6), **hashes** (MD5, SHA1, SHA256), **domains**, **URLs**, and **email addresses**.

* **Extensive File Support** 📂
    * Processes a broad variety of file types, including plain text (`.txt`, `.csv`), spreadsheets (`.xlsx`, `.xls`), documents (`.docx`, `.pdf`), and emails (`.msg`, `.eml`).
    * Includes a specialized parser for network traffic captures (`.pcap`), capable of reconstructing and saving files transferred over unencrypted HTTP.

---
## Intelligent Analysis & Enrichment

The script goes beyond simple extraction by adding layers of context and intelligence to the raw data.

* **Automated IOC Enrichment** 🌐
    * Integrates with **AbuseIPDB** to retrieve reputation data for IP addresses, including an abuse confidence score, risk level, country of origin, ISP, and the top reported attack categories.
    * Uses the **VirusTotal API** to enrich hashes, domains, and URLs with malicious detection ratios and other metadata.

* **Smart Caching System** ⚡
    * Features a local caching system that saves enrichment results for 24 hours. This speeds up subsequent scans, reduces redundant API calls, and helps manage API rate limits.
    * The cache is intelligent enough to remember `404 Not Found` results, preventing the script from wasting API quota on IOCs that are known not to be in VirusTotal's database.

* **Contextual Linking & Filtering** 🔗
    * Actively filters out "generic" IOCs from trusted providers like Google and AWS to reduce noise and help you focus on relevant threats. This categorization is done both before the scan and dynamically after enrichment for improved accuracy.
    * Creates links between IOCs by discovering new domains from IP enrichment and porting over contextual data like the country code.

---
## Comprehensive Reporting

Results are presented in clear, actionable, and user-selectable formats.

* **Multi-Format Reports** 📊
    * Generates reports in **CSV** for spreadsheet analysis, **JSON** for easy integration with other tools, and a polished **HTML** format for presentation.
    * The interactive HTML report features an **Executive Summary** of high-risk IOCs, collapsible sections for easy navigation, and a clean, modern design.

* **Secure Output Options** 🛡️
    * Includes a "defanging" feature that makes IOCs non-clickable in reports (e.g., `1.2.3.4` becomes `1[.]2[.]3[.]4`) to prevent accidental exposure to malicious sites.

---
## User-Focused Design

Grabipy is built to be robust, user-friendly, and easy to manage.

* **Interactive & Guided Workflow** ▶️
    * Features a simple command-line menu to guide you through the process.
    * Provides granular control over the scan, allowing you to choose whether to scan email attachments, hash source files, and select your preferred report formats.

* **Automated Setup & Secure Configuration** ⚙️
    * On its first run, the script automatically checks for all required libraries and offers to install them in a single batch.
    * API keys are stored securely in an external `config.ini` file, so you don't have to enter them every time you run a scan.
  
---

## 🛠️ Prerequisites

To run Grabipy, you need **Python 3** installed on your system. The script is designed to be self-contained and will handle its own library dependencies. Please use an elevated command prompt

On the first run, the script will automatically check for all required third-party libraries and will prompt you for permission to install them in a single batch. (This can take up to 15 mins depending on connection and library size.)

The required libraries are:
* **requests**: For making API calls to enrichment services like VirusTotal and AbuseIPDB.
* **chardet**: For automatically detecting the character encoding of text-based files to prevent parsing errors.
* **python-docx**: For parsing Microsoft Word `.docx` files.
* **pdfplumber**: For extracting text from `.pdf` documents.
* **extract-msg**: For handling Microsoft Outlook `.msg` files.
* **pandas** & **openpyxl**: For reading data from Microsoft Excel `.xlsx` and `.xls` spreadsheets.
* **tqdm**: Provides progress bars for a better user experience during long operations.
* **tldextract**: For accurately extracting the root domain from URLs and email addresses.
* **beautifulsoup4**: For parsing HTML content, primarily from emails.
* **scapy**: Used for parsing and analyzing `.pcap` network capture files.
* **six**, **numpy**, **python-dateutil**, **pytz**: Additional libraries required by other dependencies to function correctly.

---

### 🚀 Usage

1.  **Save the Script**: Save the provided code as a Python file, for example, `grabipy.py`.

2.  **First Run & Installation**: Open your terminal or command prompt, navigate to the script's directory, and run it. The script will find all missing dependencies and ask for permission to install them.
    ```bash
    python grabipy.py
    ```

3.  **Fast Startup (Recommended for Daily Use)**: After the first run, you can use the `--skip-check` flag to bypass the dependency check for a much faster start.
    ```bash
    python grabipy.py --skip-check
    ```

4.  **Main Menu**: You will be presented with the main menu.
    ```
    --- Main Menu ---
    1. Run IOC Extraction & Enrichment
    2. Set up/update API keys
    3. Guide
    4. Exit
    ```

5.  **Enter API Keys (Optional but Recommended)**: If you choose to enrich IOCs (Option 1) and your API keys are not configured, the script will prompt you to set them up immediately. You can also manually set them up by choosing Option `2`. The keys are necessary for the enrichment process and will be saved to `config.ini`.

6.  **Start Extraction**: Choose option `1` and follow the prompts. The script will ask for the file or folder path and other preferences.

7.  **View Report**: A CSV report with the extracted and enriched data will be generated in the same directory as the script.

---

### ⚠️ Limitations

* **File Type Coverage**: While the script supports a wide range of common file types, it may not be able to parse content from all files, especially those with custom or proprietary formats.
* **PCAP Parsing**: The PCAP file analysis is limited to extracting IOCs and reconstructing files from unencrypted HTTP traffic. It does not support HTTPS or other encrypted protocols.
* **Memory Usage**: While the script is designed to be memory-efficient, processing extremely large files (e.g., multi-gigabyte PCAP files) may still be resource-intensive.
* **API Dependencies & Rate Limits**:
    * Enrichment functionality is entirely dependent on the availability and accuracy of the AbuseIPDB and VirusTotal APIs.
    * **AbuseIPDB**: The free tier has a daily limit of 1,000 requests.
    * **VirusTotal**: The public API has tight constraints (e.g., 4 requests per minute). The script includes a built-in delay to manage these rates, but the enrichment process can be slow.

---

### Error Handling

#### SSL Errors on Corporate Networks

If you are on a corporate network that inspects traffic, you may encounter an `SSLError` or `CERTIFICATE_VERIFY_FAILED` error. This happens because your network's security tools are intercepting the connection.

```
Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain'))
```

You have two options to resolve this:

1.  **Quick Fix (Less Secure)**: Modify the script to skip SSL verification. In the `Enricher` class, find every `requests.get(...)` call and add `verify=False`.
    > **Security Warning**: Disabling verification means your connection is no longer fully secure. Only do this if you are on a network you trust.

2.  **Proper Fix (Secure)**: Obtain the public root certificate file (usually a `.pem` or `.crt` file) from your IT or cybersecurity department. Save this file and point the script to it:
    ```python
    # Example of the secure method
    resp = requests.get(..., verify='C:\\path\\to\\your\\company-cert.pem')
