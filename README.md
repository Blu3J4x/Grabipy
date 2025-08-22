# Grabipy by Blu3J4x
## Threat Intelligence &amp; Enrichment Tool

This repository contains **Grabipy**, a robust and user-friendly Python script designed for cybersecurity analysts and researchers. It automates the process of extracting, parsing, and enriching Indicators of Compromise (IOCs) from a wide range of file types, providing a comprehensive and efficient way to analyze potential threats.

**Welcome!** This tool was designed by sheer vibe coding. I'm by no means a Python wizard; I just understand how to read it.
Being a creative person, I was able to leverage AI to help me vibe code my way to this wonderful little tool, which I named **Grabipy!**

---

### Features

* **Wide File Support**: The tool is capable of processing a broad range of common file formats, including plain text (`.txt`), spreadsheets (`.csv`, `.xlsx`), documents (`.docx`, `.pdf`), email archives (`.eml`, `.msg`), and network traffic captures (`.pcap`).
* **Comprehensive IOC Extraction**: It automatically identifies and extracts various types of IOCs, including:
    * **IP Addresses** (IPv4)
    * **Hashes** (MD5, SHA1, SHA256)
    * **Domains & URLs** (with automatic defanging to prevent accidental clicks)
    * **Email Addresses** and associated **Message-IDs**
* **Advanced Parsing Capabilities**:
    * **Email Analysis**: It can parse email bodies and headers and, optionally, analyze **email attachments** to extract hashes and other IOCs.
    * **Network Analysis**: The tool can process `.pcap` files, extract IOCs from network traffic, and automatically reconstruct and save files transferred over unencrypted HTTP connections.
* **Automated Enrichment**: It provides the option to enrich collected IOCs by querying public threat intelligence services like **AbuseIPDB** for IP reputation and **VirusTotal** for hash, domain, and URL reputation. This gives you valuable context and risk scoring directly in the output.
* **Enhanced Usability**: The script features a streamlined, interactive command-line interface, securely stores API keys in a separate `config.ini` file, and uses memory-efficient methods to handle large files without performance degradation.
* **Detailed Reporting**: All findings are compiled into a single, clean, timestamped CSV report that includes the extracted IOCs, their source files, and all enrichment data for easy analysis and sharing.

---

### Limitations

* **Encrypted Traffic**: The script's PCAP parsing is limited to **unencrypted HTTP traffic on port 80** and cannot analyze encrypted HTTPS or other secure protocols.
* **File Format Dependence**: The script's ability to extract IOCs from a file is highly dependent on the file's internal structure and content. Some malicious documents may be designed as lures without readable text, which could cause the script to miss IOCs hidden in other components.
* **Third-Party Dependencies**: The script relies on a number of external Python libraries that need to be installed on the user's system to function correctly.

---

### Required Libraries

The script automatically checks for and prompts you to install these libraries if they are missing.

* **python-docx**
* **pdfplumber**
* **extract-msg**
* **pandas**
* **openpyxl**
* **tqdm**
* **tldextract**
* **beautifulsoup4**
* **scapy**
* **six**
* **numpy**
* **python-dateutil**
* **pytz**
