### 🕵️ Grabipy: Threat Intelligence & IOC Enrichment Tool
## Created by Blu3J4x

This repository contains **Grabipy**, a robust and user-friendly Python script designed for cybersecurity analysts and researchers. It automates the process of extracting, parsing, and enriching Indicators of Compromise (IOCs) from a wide range of file types, providing a comprehensive and efficient way to analyze potential threats.

This tool was designed by sheer vibe coding. I'm by no means a Python wizard; I just understand how to read it. Being a creative person, I was able to leverage AI to help me vibe code my way to this wonderful little tool, which I named **Grabipy**\!

**Table of Contents**

  * [✨ Key Features](https://github.com/Blu3J4x/Grabipy/tree/main?tab=readme-ov-file#-key-features)
  * [🛠️ Prerequisites](https://github.com/Blu3J4x/Grabipy/tree/main?tab=readme-ov-file#-prerequisites)
  * [🚀 Usage](https://github.com/Blu3J4x/Grabipy/tree/main?tab=readme-ov-file#-usage)
  * [⚠️ Limitations](https://github.com/Blu3J4x/Grabipy/tree/main?tab=readme-ov-file#limitations)

-----

### Key Features

  * **Wide File Support**: 📂 Processes a broad range of file types including `.txt`, `.csv`, `.xlsx`, `.docx`, `.pdf`, `.msg`, `.eml`, and `.pcap`.
  * **Automated Enrichment**: 🌐 Optionally enriches collected IOCs against threat intelligence services like AbuseIPDB and VirusTotal to provide valuable context and risk scoring.
  * **Advanced Parsing**: 📧 Extracts email headers, Message-IDs, and automatically reconstructs and saves files transferred over unencrypted HTTP connections from PCAP files.
  * **Interactive Workflow**: ➡️ Features a streamlined command-line interface with an interactive menu for easy navigation.
  * **Secure API Key Management**: 🔑 Stores API keys securely in a separate `config.ini` file, so you do not have to re-enter them on every run.
  * **Comprehensive Output**: 📊 Generates a timestamped CSV report (`ioc_enriched_report_YYYYMMDD_HHMMSS.csv`) with all extracted IOCs, their source files, and enrichment data.
  * **Defanging Capability**: 🛡️ Offers the option to defang the output, replacing periods with `[.]` and `http/https` with `hxxp/hxxps` to prevent accidental clicks.

-----

### 🛠Prerequisites

To run this script, you need to have **Python 3** installed. The script also requires several third-party libraries. It will automatically check for and prompt you to install these dependencies on the first run. The dependencies are:

  * `python-docx`: For parsing `.docx` files.
  * `pdfplumber`: For extracting text from `.pdf` documents.
  * `extract-msg`: For handling `.msg` (Outlook) files.
  * `pandas`: Used for reading data from `.xlsx` spreadsheets.
  * `openpyxl`: A dependency for `pandas` to read/write `.xlsx` files.
  * `tqdm`: Provides a progress bar for a better user experience during long tasks.
  * `tldextract`: Extracts the top-level domain from URLs and email addresses.
  * `beautifulsoup4`: For parsing HTML content from emails.
  * `scapy`: Used for parsing and analyzing `.pcap` network capture files.
  * `six`, `numpy`, `python-dateutil`, `pytz`: Additional libraries required by other dependencies.

-----

### Usage

1.  **Save the Script**: Save the provided code as a Python file, for example, `grabipy.py`.

2.  **Run the Script**: Open your terminal or command prompt and run the script.

    ```bash
    python3 grabipy.py
    ```

3.  **Main Menu**: You will be presented with the main menu.

    ```
    --- Main Menu ---
    1. Run IOC Extraction & Enrichment
    2. Set up/update API keys
    3. Exit
    ```

4.  **Enter API Keys (Optional but Recommended)**: Choose option `2` to set up your API keys. The script will securely save them in a `config.ini` file. These keys are necessary for the enrichment process.

5.  **Start Extraction**: Choose option `1` and follow the prompts. The script will ask for the file or folder path and whether to scan email attachments.

6.  **Enrichment**: After extraction, the script will detect which API keys are available and will only prompt you to enrich IOC types that have a corresponding key. This prevents unnecessary prompts for services you can't use.

7.  **Defang Output**: You will be asked if you want to defang the output. Choosing `'y'` will make the IOCs safer to share in reports.

8.  **View Report**: A CSV report with the extracted and enriched data will be generated in the same directory as the script. The file name will include a timestamp for easy tracking.

-----

### Limitations

  * **File Type Coverage**: While the script supports a wide range of common file types, it may not be able to parse content from all files, especially those with custom or proprietary formats.
  * **PCAP Parsing**: The PCAP file analysis is limited to extracting IOCs and reconstructing files from unencrypted HTTP traffic. It does not support HTTPS or other encrypted protocols.
  * **False Positives**: The regex patterns used for IOC extraction, while robust, may sometimes lead to false positives (e.g., a hash-like string that is not a true hash).
  * **Memory Usage**: While the script is designed to be memory-efficient, processing extremely large files (e.g., multi-gigabyte PCAP files) may still be resource-intensive.
  * **API Dependencies & Rate Limits**:
      * Enrichment functionality is entirely dependent on the availability and accuracy of the AbuseIPDB and VirusTotal APIs. The script will skip enrichment for IOC types if the corresponding API key is not provided.
      * **AbuseIPDB**: The free tier has a daily limit of 1,000 requests. For a large volume of IOCs, this limit can be quickly reached.
      * **VirusTotal**: The public API has tight constraints, including a limit of 4 requests per minute and 500 requests per day. The public API is also for non-commercial use only. The script includes a built-in delay to manage these rates, but the enrichment process can be slow.
