# 🕵️ Grabipy: Threat Intelligence & IOC Enrichment Tool
## Created by Blu3J4x

Grabipy is a robust and user-friendly Python script for threat intelligence. It automatically scans files and folders to extract Indicators of Compromise (IOCs), including IPs, hashes (MD5, SHA1, SHA256), domains, URLs, and email addresses, and enriches them using external APIs.

<img width="600" height="458" alt="image" src="https://github.com/user-attachments/assets/4e884204-100f-4ba0-b287-25f4512f5976" />


---

### ✨ Key Features

* **Wide File Support**: 📂 Processes a broad range of file types including `.txt`, `.csv`, `.xlsx`, `.docx`, `.pdf`, `.msg`, `.eml`, and `.pcap`.
* **Automated Enrichment**: 🌐 Optionally enriches collected IOCs against threat intelligence services like **AbuseIPDB** and **VirusTotal** to provide valuable context and risk scoring.
* **Advanced Parsing**: 📧 Extracts email headers, attachments, Message-IDs, and automatically reconstructs and saves files transferred over unencrypted HTTP connections from PCAP files.
* **Smart, Interactive Workflow**: ➡️ Features a streamlined command-line interface with an interactive menu. If API keys are missing, it will prompt you to set them up on the spot.
* **Efficient Dependency Management**: ⚙️ On first run, the script checks for all missing libraries and installs them in a single batch for a quick setup.
* **Fast Startup Option**: ⚡ For daily use, you can bypass the dependency check for an instant start using the `--skip-check` flag.
* **Secure API Key Management**: 🔑 Stores API keys securely in a separate `config.ini` file, so you do not have to re-enter them on every run.
* **Comprehensive Output**: 📊 Generates a timestamped CSV report (`ioc_enriched_report_YYYYMMDD_HHMMSS.csv`) with all extracted IOCs, their source files, and enrichment data.
* **Defanging Capability**: 🛡️ Offers the option to defang the output, replacing periods with `[.]` and `http/https` with `hxxp/hxxps` to prevent accidental clicks.

---

### 🛠️ Prerequisites

To run this script, you need to have **Python 3** installed. The script also requires several third-party libraries. It will automatically check for and prompt you to install these dependencies in a single batch on the first run. (This could take 10 - 15 mins as they are extensive libraries)

* `python-docx`: For parsing `.docx` files.
* `pdfplumber`: For extracting text from `.pdf` documents.
* `extract-msg`: For handling `.msg` (Outlook) files.
* `pandas` & `openpyxl`: For reading data from `.xlsx` spreadsheets.
* `tqdm`: Provides progress bars for a better user experience.
* `tldextract`: Extracts the top-level domain from URLs and email addresses.
* `beautifulsoup4`: For parsing HTML content from emails.
* `scapy`: Used for parsing and analyzing `.pcap` network capture files.
* `six`, `numpy`, `python-dateutil`, `pytz`: Additional libraries required by other dependencies.

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
    3. Exit
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
