***

## Grabipy v1.5 - The "Context & Clarity" Update 29/08/2025

This is a major update focused on improving the accuracy of IOC extraction, adding intelligence context between IOCs, and completely overhauling the reporting engine for better clarity and usability.

---

### 🚀 Major New Features

* **Dynamic Post-Enrichment IOC Segregation:**
    * IOCs are now re-evaluated **after** enrichment. If an IP's ISP is identified as a major provider (e.g., Google, Microsoft, AWS) or its enriched domain is a known generic service, it is automatically moved from the main results to the "Generic IOCs" list. This dramatically reduces false positives and helps you focus on genuinely suspicious indicators.
    * This logic has been extended to **Domains**, **URLs**, and **Emails**, ensuring all IOC types are correctly categorized based on the latest data.

* **Intelligent IOC Context Porting:**
    * When an IP is enriched, the script now automatically extracts any associated domain. If this domain is new, it's **added to the enrichment queue**.
    * Crucially, contextual data like the **Country Code** from the IP is ported over to the newly discovered domain's enrichment data, creating a link between the two indicators.

* **User-Controlled Source File Hashing:**
    * You are now prompted whether you want to perform a full hash (MD5, SHA1, SHA256) of all source files. This was previously an unconditional (and sometimes slow) process. This change gives you more control over the scan's scope and speed.

* **Multi-Format Report Selection:**
    * You can now choose your desired output formats at the end of a scan. Enter a comma-separated list (e.g., `html, csv`) to generate only the reports you need. The script defaults to CSV if no selection is made.

---

### ✨ Enhancements & Quality of Life

* **Completely Rebuilt HTML Report:**
    * **Modern UI:** A clean, professional, and readable design with improved styling and typography.
    * **Executive Summary:** A new "Top IOCs for Review" section is automatically generated at the top, highlighting all IPs with an Abuse Score >= 30 and any other IOC with a malicious detection.
    * **Interactive Tables:** All report sections are now collapsible, allowing you to easily show or hide data.
    * **Sticky Navigation Bar:** A navigation bar at the top of the report allows you to jump directly to any IOC section (IPs, Hashes, Domains, etc.).
    * **Improved Data Layout:** Enrichment data is now broken out into logical columns (Risk Level, Score, Country, etc.) for easier scanning and comparison, rather than being grouped in a single cell.

* **Smarter API & Cache Handling:**
    * **404 Caching:** When VirusTotal returns a `404 Not Found` for a hash, domain, or URL, this result is now **cached**. This prevents the script from wasting API quota by repeatedly querying for IOCs that are known not to exist on the platform.
    * The internal cache logic now tracks whether a result was served from the cache or a live API call, improving data handling.

* **More Robust IOC Parsing:**
    * **IP Validation:** The script now uses a more robust method for identifying IPs. It finds all potential matches and then validates each one using the `ipaddress` library, significantly reducing false positives from version numbers or other similar patterns.
    * **Encoding Detection:** The script now uses `chardet` to automatically detect the encoding of `.txt` and `.csv` files, preventing errors when processing files not saved in standard UTF-8 or UTF-16 formats.

* **Dynamic CSV Reporting:**
    * The CSV report headers are now generated dynamically based on the available enrichment data. This ensures that all collected information, including new fields like "Report Categories" from AbuseIPDB, is included in the report without data loss.

---

### 🐛 Bug Fixes & Stability

* **Corrected File Hashing Logic:** Fixed a bug where source files were being hashed unconditionally within the extraction function. Hashing is now correctly handled in the main orchestration function and is subject to user consent.
* **Fixed IP Report Category Parsing:** Corrected an issue where the script would fail to parse the "Report Categories" from AbuseIPDB if a single report contained multiple category IDs.
* **Graceful SSL Error Handling:** A more detailed and user-friendly error message is now displayed once if an SSL certificate verification fails (common on corporate networks), and all further enrichment is halted cleanly.
* **Improved HTML Risk Scoring:** The logic for color-coding risk levels in the HTML report is now more robust and correctly handles cases where an IOC has a malicious score but no categorical "Risk Level."

---

### 🔧 Refactoring & Code Quality

* **Memory-Efficient File Reading:** The `read_file_content` function for text-based files has been converted to a Python generator (`yield`). This reads files line-by-line instead of loading the entire file into memory, drastically improving performance and reducing memory usage on very large files.
* **Separation of Concerns:** User input logic for enrichment choices has been moved from the `enrich_iocs` function into the `main_menu` loop. The enrichment function now accepts boolean flags, making the code cleaner and easier to maintain.
* **Code Consolidation:** Duplicate code for processing and sorting IOCs for reports has been consolidated into helper functions (`process_ioc_dict`, `write_csv_section`) to improve readability and reduce redundancy.

---
## Grabipy v1.4 Changelog 27/08/2025
---
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
