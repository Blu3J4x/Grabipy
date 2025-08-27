## Grabipy v1.4 Changelog

Version 1.4 introduces significant enhancements focused on performance, usability, and reporting capabilities.

### 🚀 New Features

* **Multi-Format Reporting**: You can now generate reports in **JSON** and **HTML** formats in addition to the classic CSV. The script prompts the user to select their desired output formats (e.g., `csv, json, html`).
* **Enrichment Caching**: To significantly speed up re-scans and reduce API usage, IOC enrichment results are now **cached locally** in an `enrichment_cache.json` file. Cached results are valid for 24 hours.
* **In-Depth IP Reputation**: IP enrichment via AbuseIPDB is now more detailed. For IPs with an abuse score greater than 25, the script makes a second API call to fetch the **top 3 reported abuse categories** (e.g., Port Scan, Hacking, Brute-Force), providing much richer context.
* **Interactive User Guide**: A new main menu option has been added to display a **step-by-step user guide**, making it easier for new users to get started with setup and scanning.

---

### ✨ Improvements & Quality of Life Changes

* **Major UI/UX Overhaul**:
    * The main menu has been redesigned with a new **ASCII art banner** and clearer, more descriptive options.
    * The script flow is more logical, guiding the user through scanning, enrichment, and report generation.
* **Robust SSL/TLS Error Handling**: The script can now gracefully handle `SSLError` exceptions, which are common on corporate networks with SSL inspection. It will print a **detailed, one-time warning** and halt further enrichment attempts instead of repeatedly failing.
* **Refactored Reporting Logic**: The code for generating reports has been modularized. A new `structure_report_data` function consolidates all IOCs into a single, clean structure before passing it to the new `write_json_report` and `write_html_report` functions. This makes the code cleaner and easier to maintain.
