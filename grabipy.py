#!/usr/bin/env python3
"""
Current Version: 1.3
Grabipy – A robust and user-friendly Python script for threat intelligence.

This tool automatically scans files and folders to extract Indicators of Compromise (IOCs)
including IPs, hashes (MD5, SHA1, SHA256), domains, URLs, and email addresses.

Features:
- Wide File Support: Processes .txt, .csv, .xlsx, .docx, .pdf, .msg, .eml, and .pcap files.
- Automated Enrichment: Optionally enriches collected IOCs against threat intelligence services
  like AbuseIPDB and VirusTotal to provide valuable context and risk scoring.
- Advanced Parsing: Extracts email headers, Message-IDs, and automatically reconstructs
  and saves files transferred over unencrypted HTTP connections in PCAP files.
- Enhanced Usability: Streamlined workflow with an interactive menu, secure API key storage
  in a separate 'config.ini' file, and efficient, memory-safe file handling.
- Comprehensive Output: Generates a timestamped CSV report with all extracted IOCs,
  and enrichment data.
- Defanging Capability: Offers the option to defang the output, replacing periods with [.] 
  and http/https with hxxp/hxxps to prevent accidental clicks.
"""

import os, re, ipaddress, requests, csv, time, getpass, sys, subprocess, email, struct
from urllib.parse import urlparse, unquote
from collections import Counter, defaultdict
from datetime import datetime
import base64
import hashlib
import configparser
from requests.exceptions import RequestException

# === Console colors ===
class color:
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    END = '\033[0m'

# === Dependency check ===
def check_and_install_dependencies():
    """Checks for all required dependencies and installs them in a single batch."""
    
    # A single dictionary mapping the import name to the pip install name
    all_dependencies = {
        "docx": "python-docx",
        "pdfplumber": "pdfplumber",
        "extract_msg": "extract-msg",
        "pandas": "pandas",
        "openpyxl": "openpyxl",
        "tqdm": "tqdm",
        "tldextract": "tldextract",
        "bs4": "beautifulsoup4",
        "scapy": "scapy",
        "six": "six",
        "numpy": "numpy",
        "dateutil": "python-dateutil",
        "pytz": "pytz"
    }
    
    missing_packages = []
    print(f"{color.INFO}[*] Checking for required modules...{color.END}")
    for module_name, pip_name in all_dependencies.items():
        try:
            __import__(module_name)
        except ImportError:
            missing_packages.append(pip_name)
            
    if missing_packages:
        print(f"\n{color.WARNING}[!] The following required modules are missing:{color.END}")
        for pkg in missing_packages:
            print(f"  - {pkg}")
            
        choice = input(f"\nDo you want to try installing them now? [Y/n]: ").strip().lower()
        if choice in ('', 'y', 'yes'):
            try:
                print(f"{color.INFO}[*] Installing {len(missing_packages)} package(s)...{color.END}")
                # Installs all missing packages in one command
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", *missing_packages])
                print(f"\n{color.SUCCESS}[✓] All dependencies installed. Please re-run the script to start.{color.END}")
            except subprocess.CalledProcessError:
                print(f"{color.ERROR}[✗] Failed to install one or more packages. Please try installing them manually.{color.END}")
            sys.exit(1) # Exit after installation attempt so the script can be re-run cleanly
        else:
            print(f"{color.ERROR}[✗] Required modules are missing. Exiting.{color.END}")
            sys.exit(1)
    else:
        print(f"{color.SUCCESS}[✓] All dependencies are satisfied.{color.END}")

# Run the dependency check at the start of the script
check_and_install_dependencies()

# Safe imports
from docx import Document
import pdfplumber
import extract_msg
import pandas as pd
from tqdm import tqdm
import tldextract
from bs4 import BeautifulSoup
from scapy.all import rdpcap, IP, TCP, UDP, Raw, hexdump
from scapy.layers.http import HTTP

# === Config & API Keys ===
CONFIG_FILE = 'config.ini'

def setup_config():
    """Prompts user for API keys and saves them to a config file."""
    config = configparser.ConfigParser()
    config['API_KEYS'] = {}
    print(f"\n{color.INFO}[*] Please enter your API keys. They will be saved to '{CONFIG_FILE}'{color.END}")
    config['API_KEYS']['AbuseIPDB_Key'] = getpass.getpass("Enter AbuseIPDB API key: ").strip()
    config['API_KEYS']['VirusTotal_Key'] = getpass.getpass("Enter VirusTotal API key: ").strip()

    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)
    print(f"{color.SUCCESS}[✓] API keys saved to '{CONFIG_FILE}'. You will not be asked for them again.{color.END}")
    return config['API_KEYS']['AbuseIPDB_Key'], config['API_KEYS']['VirusTotal_Key']

def load_config():
    """Loads API keys from a config file."""
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        return None, None
    config.read(CONFIG_FILE)
    try:
        abuse_key = config['API_KEYS']['AbuseIPDB_Key']
        vt_key = config['API_KEYS']['VirusTotal_Key']
        return abuse_key, vt_key
    except (KeyError, configparser.NoSectionError):
        print(f"{color.ERROR}[✗] Error reading API keys from '{CONFIG_FILE}'. Please re-enter them.{color.END}")
        return None, None

# === API Endpoints ===
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
VT_FILE_URL = 'https://www.virustotal.com/api/v3/files/'
VT_DOMAIN_URL = 'https://www.virustotal.com/api/v3/domains/'
VT_URLS_URL = 'https://www.virustotal.com/api/v3/urls/'

# === Regex (More specific hash regex for improved accuracy) ===
RE_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_HASH = re.compile(f"(?:{RE_MD5.pattern}|{RE_SHA1.pattern}|{RE_SHA256.pattern})")
RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_URL = re.compile(r"\b(?:http|https|hxxp|hxxps)://\S+\b", re.IGNORECASE)

# === Risk scoring ===
def get_risk_level(score):
    if score >= 70: return "High"
    elif score >= 30: return "Medium"
    else: return "Low"

# === Helpers ===
def undefang(url: str) -> str:
    url = url.replace("hxxp://", "http://").replace("hxxps://", "https://")
    url = url.replace("[.]", ".").replace("(.)", ".")
    url = url.replace("2F", "/").replace("40", "@").replace("%/", "/").replace("%/%/", "//")
    return url
    
def defang(ioc_type: str, ioc: str) -> str:
    """Defangs an IOC to prevent it from being clickable."""
    if ioc_type == 'IP':
        return ioc.replace(".", "[.]")
    elif ioc_type == 'Domain':
        return ioc.replace(".", "[.]")
    elif ioc_type == 'URL':
        url = ioc.replace("http://", "hxxp://").replace("https://", "hxxps://")
        url = url.replace(".", "[.]")
        return url
    return ioc

def get_root_domain(url_or_email):
    url_or_email = url_or_email.strip().strip("<>").strip('"')
    if "@" not in url_or_email:
        parsed = tldextract.extract(undefang(url_or_email))
        if parsed.domain and parsed.suffix: return f"{parsed.domain}.{parsed.suffix}"
        return url_or_email
    else:
        domain = url_or_email.split("@")[-1]
        parsed = tldextract.extract(domain)
        if parsed.domain and parsed.suffix: return f"{parsed.domain}.{parsed.suffix}"
        return domain

def clean_email(email_address):
    """Extracts the email address from a string."""
    if not email_address: return ""
    match = re.search(RE_EMAIL, email_address)
    return match.group(0) if match else ""
    
def extract_safelink(url):
    """Extracts the real URL from a Microsoft SafeLink wrapper."""
    if 'safelinks.protection.outlook.com' in url.lower():
        try:
            parsed = urlparse(url)
            query_params = dict(qp.split('=') for qp in parsed.query.split('&') if '=' in qp)
            if 'url' in query_params:
                unwrapped_url = unquote(query_params['url'])
                return unwrapped_url
        except Exception as e:
            tqdm.write(f"{color.WARNING}[!] Failed to parse SafeLink URL: {url} - {e}{color.END}")
    return url
    
def clean_message_id(message_id):
    """Removes the leading and trailing angle brackets from a Message-ID."""
    if message_id and message_id.startswith('<') and message_id.endswith('>'):
        return message_id[1:-1]
    return message_id

# === Generic IOC check ===
def is_generic_ioc(ioc, ioc_type):
    """Checks if an IOC belongs to a known generic/trusted entity."""
    
    # Common domains for Google, Microsoft, AWS, etc.
    GENERIC_DOMAINS = {
        "google.com", "gmail.com", "gstatic.com", "googlevideo.com", 
        "googleusercontent.com", "youtube.com", "windows.net", "microsoft.com", 
        "msftncsi.com", "azure.com", "office.com", "outlook.com", "hotmail.com", 
        "live.co.uk", "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", 
        "akamaihd.net", "apple.com", "icloud.com", "github.com", "mailchimp.com", 
        "dropbox.com", "onedrive.live.com", "logmein.com", "facebook.com", 
        "twitter.com", "linkedin.com"
    }
    
    # Common IP ranges for Google, Microsoft, AWS, etc.
    GENERIC_IP_RANGES = [
        # Google
        "8.8.8.0/24", "8.8.4.0/24", "172.217.0.0/16", "142.250.0.0/16", "216.58.192.0/19",
        # Microsoft (Azure/Office 365)
        "40.76.0.0/16", "52.96.0.0/11", "13.107.6.152/31", "13.107.18.152/31",
        # Amazon AWS
        "3.0.0.0/5", "18.200.0.0/13", "34.192.0.0/12", "52.0.0.0/8", "54.240.0.0/12",
        "72.0.0.0/8", "76.0.0.0/8", "99.80.0.0/12", "107.20.0.0/14", "204.236.192.0/18",
        # Cloudflare
        "104.16.0.0/12", "172.64.0.0/13", "188.114.96.0/20",
    ]

    # Hashes are never generic, so return False
    if ioc_type == "Hash":
        return False
        
    # Check IPs against CIDR blocks
    if ioc_type == "IP":
        try:
            ip_obj = ipaddress.ip_address(ioc)
            for network in GENERIC_IP_RANGES:
                if ip_obj in ipaddress.ip_network(network):
                    return True
        except ValueError:
            pass # Invalid IP, not generic
            
    # Check Domains and URLs against known domains
    if ioc_type in ["Domain", "URL"]:
        root_domain = get_root_domain(ioc)
        if root_domain in GENERIC_DOMAINS:
            return True

    return False

# === File collector ===
SUPPORTED_EXTENSIONS = ['.txt', '.csv', '.xlsx', '.xls', '.docx', '.pdf', '.msg', '.eml', '.pcap']

def get_files_from_path(path):
    path = os.path.expanduser(path)
    path = os.path.normpath(path)
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        if ext in SUPPORTED_EXTENSIONS: return [path]
        else: raise ValueError(f"Unsupported file type: {path}")
    elif os.path.isdir(path):
        all_files = []
        for root, dirs, files in os.walk(path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in SUPPORTED_EXTENSIONS:
                    all_files.append(os.path.join(root, file))
        return all_files
    else:
        raise ValueError(f"Path does not exist: {path}")

# === File hashing function ===
def hash_file(filepath):
    """Calculates MD5, SHA1, and SHA256 hashes for a given file."""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return [
            {'hash': md5_hash.hexdigest(), 'type': 'md5', 'source_file': filepath},
            {'hash': sha1_hash.hexdigest(), 'type': 'sha1', 'source_file': filepath},
            {'hash': sha256_hash.hexdigest(), 'type': 'sha256', 'source_file': filepath}
        ]
    except Exception as e:
        tqdm.write(f"{color.ERROR}[!] Error hashing file {filepath}: {e}{color.END}")
        return []

# === File parsing ===
def read_file_content(file_path):
    """Generator to read file content line by line for memory efficiency."""
    try:
        if file_path.endswith(".txt") or file_path.endswith(".csv"):
            with open(file_path, 'r', encoding='utf-16', errors='ignore') as f:
                for line in f:
                    yield line.strip()
        elif file_path.endswith(".xlsx"):
            df = pd.read_excel(file_path)
            for item in df.astype(str).values.flatten():
                yield item
        elif file_path.endswith(".docx"):
            doc = Document(file_path)
            for p in doc.paragraphs:
                yield p.text
        elif file_path.endswith(".pdf"):
            with pdfplumber.open(file_path) as pdf:
                for page in pdf.pages:
                    txt = page.extract_text()
                    if txt:
                        for line in txt.splitlines():
                            yield line
        elif file_path.endswith(".msg"):
            msg = extract_msg.Message(file_path)
            body_text = msg.body or ""
            for line in body_text.splitlines():
                yield line
        else:
            # Fallback for unsupported file types
            tqdm.write(f"{color.WARNING}[!] Unsupported file type for direct content read: {file_path}{color.END}")
            yield ""
    except Exception as e:
        tqdm.write(f"{color.ERROR}[✗] Error reading {file_path}: {e}{color.END}")

def read_eml_file(file_path, scan_attachments=False):
    """Specialized function for parsing .eml files."""
    text, attachments, headers_info, html_urls = [], [], [], []
    try:
        import email.policy
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
        headers_info.append({
            'From': msg.get('From'),
            'Reply-To': msg.get('Reply-To'),
            'Return-Path': msg.get('Return-Path'),
            'Message-ID': msg.get('Message-ID'),
            'X-Sender-IP': msg.get('X-Sender-IP')
        })
        
        def decode_payload(part):
            payload = part.get_payload(decode=True)
            if not payload: return "", ""
            charset = part.get_content_charset() or "utf-8"
            try: 
                return payload.decode(charset, errors="ignore"), part.get_content_type()
            except: 
                return payload.decode("utf-8", errors="ignore"), part.get_content_type()
        
        for part in msg.walk():
            decoded_content, ctype = decode_payload(part)
            disp = part.get_content_disposition()
            
            if disp == "attachment" and scan_attachments:
                payload = part.get_payload(decode=True)
                filename = part.get_filename() or "unknown_filename"
                if payload: attachments.append((payload, filename))
            
            if decoded_content:
                if ctype == "text/html":
                    soup = BeautifulSoup(decoded_content, 'html.parser')
                    for a_tag in soup.find_all('a', href=True):
                        html_urls.append(a_tag['href'])
                    for img_tag in soup.find_all('img', src=True):
                        html_urls.append(img_tag['src'])
                    text.extend(soup.get_text().splitlines())
                elif ctype == "text/plain":
                    text.extend(decoded_content.splitlines())
                    
    except Exception as e:
        tqdm.write(f"{color.ERROR}[✗] Error reading {file_path}: {e}{color.END}")
        
    return ([line.strip() for line in text if line and line.strip()], 
            attachments, 
            headers_info, 
            html_urls)

def read_pcap_file_and_extract_files(file_path):
    """
    Reads a PCAP file and extracts IOCs (IPs, Domains, URLs) and also attempts to
    reconstruct and save transferred files.
    NOTE: This only works for unencrypted HTTP traffic.
    """
    ips = set()
    domains = set()
    urls = set()
    extracted_files = []

    try:
        packets = rdpcap(file_path)
        sessions = packets.sessions()
        
        for session_key, session_packets in sessions.items():
            if 'TCP' in session_key:
                src_ip, src_port, dst_ip, dst_port = session_key.split()
                if dst_port == '80':
                    data = b''
                    for pkt in session_packets:
                        if pkt.haslayer(Raw):
                            data += pkt[Raw].load

                    if b'HTTP/1.' in data:
                        try:
                            http_stream = HTTP(data)
                            if http_stream.haslayer('HTTP Response') and hasattr(http_stream, 'Content-Type'):
                                content_type = http_stream.Content_Type.decode('utf-8', errors='ignore')
                                content_length = int(http_stream.Content_Length.decode('utf-8')) if hasattr(http_stream, 'Content-Length') else 0
                                payload = data.split(b'\r\n\r\n', 1)[1]
                                
                                if payload and content_length > 0 and len(payload) >= content_length:
                                    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_extracted_files")
                                    os.makedirs(output_dir, exist_ok=True)
                                    filename = f"extracted_{dst_ip}_{dst_port}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                                    if 'image/jpeg' in content_type: filename += '.jpg'
                                    elif 'image/png' in content_type: filename += '.png'
                                    elif 'application/pdf' in content_type: filename += '.pdf'
                                    elif 'application/zip' in content_type: filename += '.zip'
                                    elif 'text/plain' in content_type: filename += '.txt'
                                    else: filename += '.bin'
                                    
                                    output_path = os.path.join(output_dir, filename)
                                    with open(output_path, 'wb') as f:
                                        f.write(payload)
                                    extracted_files.append(output_path)
                                    tqdm.write(f"{color.SUCCESS}[✓] Extracted file: {output_path}{color.END}")

                        except Exception as e:
                            tqdm.write(f"{color.WARNING}[!] Failed to process HTTP stream for {session_key}: {e}{color.END}")

            for pkt in session_packets:
                if pkt.haslayer(IP):
                    ips.add(pkt[IP].src)
                    ips.add(pkt[IP].dst)

                if pkt.haslayer('DNS'):
                    for qname in pkt['DNS'].qd:
                        qname_str = qname.qname.decode().strip('.')
                        ext = tldextract.extract(qname_str)
                        if ext.domain and ext.suffix:
                            domains.add(f"{ext.domain}.{ext.suffix}")
                
                if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                    if pkt.haslayer(Raw):
                        try:
                            http_payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                            match = re.search(r"Host: (.*?)\r\n", http_payload)
                            if match:
                                host = match.group(1).strip()
                                urls.add(f"http://{host}")
                        except UnicodeDecodeError:
                            pass
        
        return list(ips), list(domains), list(urls), extracted_files

    except Exception as e:
        tqdm.write(f"{color.ERROR}[✗] Error reading {file_path}: {e}{color.END}")
        return [], [], [], []

# === IOC Extraction ===
def extract_iocs_from_file(file_path, scan_attachments):
    ips = set()
    hashes = set()
    domains = set()
    urls = set()
    emails_dict = {}
    msg_ids = set()
    extracted_pcap_files = []
    
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension == ".pcap":
        pcap_ips, pcap_domains, pcap_urls, extracted_pcap_files = read_pcap_file_and_extract_files(file_path)
        ips.update(pcap_ips)
        domains.update(pcap_domains)
        urls.update(pcap_urls)
        for h_dict in [h for f in extracted_pcap_files for h in hash_file(f)]:
            hashes.add((h_dict['hash'], h_dict['type'], h_dict['source_file']))
    else:
        if file_extension == ".eml":
            lines, attachments, headers_info, html_urls = read_eml_file(file_path, scan_attachments)
        else:
            lines_generator = read_file_content(file_path)
            lines = [l for l in lines_generator]
            attachments, headers_info, html_urls = [], [], []

        def add_url_and_domain(u):
            u_defanged = undefang(u)
            u_final = extract_safelink(u_defanged)
            urls.add(u_final)
            parsed = urlparse(u_final)
            if parsed.hostname:
                add_domain_from_string(parsed.hostname)

        def add_domain_from_string(domain_string):
            domains.add(get_root_domain(domain_string))

        for u in html_urls:
            add_url_and_domain(u)

        for header in headers_info:
            for field in ['From','Reply-To','Return-Path']:
                addr = clean_email(header.get(field))
                if addr:
                    emails_dict[addr] = header.get('Message-ID','')
                    add_domain_from_string(addr.split('@')[-1])
            if header.get('X-Sender-IP'): ips.add(header['X-Sender-IP'])
            if header.get('Message-ID'): msg_ids.add(header['Message-ID'])

        for line in lines:
            line = line.split('#',1)[0].strip()
            if not line: continue
            item = undefang(line)
            
            try: ipaddress.ip_address(item); ips.add(item); continue
            except ValueError: pass

# --- NEW, MORE ROBUST PARSING LOGIC ---

            # Find all potential IOCs on the line using broad regex searches first
            ips.update(RE_IPV4.findall(item)) # Find all IPv4 addresses
            hashes.update([(h, 'md5', file_path) for h in RE_MD5.findall(item)])
            hashes.update([(h, 'sha1', file_path) for h in RE_SHA1.findall(item)])
            hashes.update([(h, 'sha256', file_path) for h in RE_SHA256.findall(item)])

            for e in RE_EMAIL.findall(item):
                ce = clean_email(e)
                emails_dict[ce] = ''
                add_domain_from_string(ce.split('@')[-1])

            for u in RE_URL.findall(item):
                add_url_and_domain(u)

            # Split the line into words and check each word individually.
            # This is great for finding domains and IPv6 addresses.
            words = re.split(r'[\s,;<>\[\]\(\)]+', item)
            for word in words:
                if not word:
                    continue
                # Check if the word is a valid IP (handles IPv6)
                try:
                    ipaddress.ip_address(word)
                    ips.add(word)
                    continue # Move to the next word
                except ValueError:
                    pass
                
                # Check if the word is a domain
                if '.' in word and '@' not in word:
                    extracted = tldextract.extract(word)
                    if extracted.domain and extracted.suffix:
                        add_domain_from_string(word)
        
        for att_bytes, att_name in attachments:
            source_name = f"{file_path} > {att_name}"
            hashes.add((hashlib.md5(att_bytes).hexdigest(), 'md5', source_name))
            hashes.add((hashlib.sha1(att_bytes).hexdigest(), 'sha1', source_name))
            hashes.add((hashlib.sha256(att_bytes).hexdigest(), 'sha256', source_name))
        
        if file_extension not in ['.eml', '.msg']:
            for h in hash_file(file_path):
                hashes.add((h['hash'], h['type'], h['source_file']))

    return (list(ips), 
            [{'hash': h[0], 'type': h[1], 'source_file': h[2]} for h in hashes], 
            list(domains), 
            list(urls), 
            emails_dict, 
            list(msg_ids),
            extracted_pcap_files)
            
# === Enricher class ===
class Enricher:
    def __init__(self, abuse_key, vt_key, abuse_delay=1.5, vt_delay=16):
        self.abuse_key, self.vt_key = abuse_key, vt_key
        self.abuse_delay, self.vt_delay = abuse_delay, vt_delay
        self.last_abuse_call = 0
        self.last_vt_call = 0

    def _wait_for_api(self, api_name):
        if api_name == 'AbuseIPDB':
            delay = self.abuse_delay
            last_call = self.last_abuse_call
        else:
            delay = self.vt_delay
            last_call = self.last_vt_call
        
        elapsed = time.time() - last_call
        if elapsed < delay:
            time.sleep(delay - elapsed)

        if api_name == 'AbuseIPDB':
            self.last_abuse_call = time.time()
        else:
            self.last_vt_call = time.time()

    def enrich_ip(self, ip):
        self._wait_for_api('AbuseIPDB')
        try:
            resp = requests.get(ABUSEIPDB_URL,
                                 headers={'Accept':'application/json','Key':self.abuse_key},
                                 params={'ipAddress':ip}, timeout=30)
            resp.raise_for_status()
            data = resp.json()['data']
            score = data.get('abuseConfidenceScore',0)
            return {'Abuse Score':score,'Risk Level':get_risk_level(score),
                    'Country':data.get('countryCode',''),'ISP':data.get('isp',''),'Domain':data.get('domain',''),
                    'Hostname(s)':", ".join(data.get('hostnames',[])) if data.get('hostnames') else '',
                    'Last Reported':data.get('lastReportedAt','')}
        except RequestException as e:
            return {'Error':str(e)}
    
    def enrich_hash(self, value):
        self._wait_for_api('VirusTotal')
        try:
            headers = {"x-apikey": self.vt_key}
            resp = requests.get(VT_FILE_URL + value, headers=headers, timeout=30)
            resp.raise_for_status()
            j=resp.json().get('data',{}).get('attributes',{})
            stats=j.get('last_analysis_stats',{})
            malicious_count=int(stats.get('malicious',0))
            note=", ".join(j.get('tags',[])) if 'tags' in j else ''
            return {'Detection Ratio':f"{malicious_count}/{sum(stats.values())}" if stats else '0/0',
                    'Harmless':stats.get('harmless',0),'Malicious':stats.get('malicious',0),
                    'Suspicious':stats.get('suspicious',0),'Undetected':stats.get('undetected',0),
                    'Type Description':j.get('type_description',''),'First Seen':j.get('first_submission_date',''),
                    'Last Seen':j.get('last_submission_date',''),'Tags':note}
        except RequestException as e:
            return {'Error':str(e)}

    def enrich_domain(self, value):
        self._wait_for_api('VirusTotal')
        try:
            headers = {"x-apikey": self.vt_key}
            resp = requests.get(VT_DOMAIN_URL + value, headers=headers, timeout=30)
            resp.raise_for_status()
            j=resp.json().get('data',{}).get('attributes',{})
            stats=j.get('last_analysis_stats',{})
            malicious_count=int(stats.get('malicious',0))
            if malicious_count >= 5:
                risk = "High"
            elif malicious_count >= 1:
                risk = "Suspicious"
            else:
                risk = "Low"
            note=", ".join(j.get('tags',[])) if 'tags' in j else ''
            return {'Risk Level':risk,'Malicious':malicious_count,
                    'Harmless':stats.get('harmless',0),'Suspicious':stats.get('suspicious',0),
                    'Undetected':stats.get('undetected',0),'Notes':note}
        except RequestException as e:
            return {'Error':str(e)}
    
    def enrich_url(self, value):
        self._wait_for_api('VirusTotal')
        try:
            headers = {"x-apikey": self.vt_key}
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            resp = requests.get(VT_URLS_URL + url_id, headers=headers, timeout=30)
            resp.raise_for_status()
            j=resp.json().get('data',{}).get('attributes',{})
            stats=j.get('last_analysis_stats',{})
            malicious_count=int(stats.get('malicious',0))
            risk="High" if malicious_count>0 else "Low"
            note=", ".join(j.get('tags',[])) if 'tags' in j else ''
            return {'Risk Level':risk,'Malicious':malicious_count,
                    'Harmless':stats.get('harmless',0),'Suspicious':stats.get('suspicious',0),
                    'Undetected':stats.get('undetected',0),'Notes':note}
        except RequestException as e:
            return {'Error':str(e)}

# === Main functions ===
def extract_iocs(file_path, scan_attachments):
    """Orchestrates the IOC extraction process from files."""
    all_ips = defaultdict(lambda: {'source_files': set(), 'enrichment': {}})
    all_hashes = defaultdict(lambda: {'source_files': set(), 'enrichment': {}, 'hash_type': ''})
    all_domains = defaultdict(lambda: {'source_files': set(), 'enrichment': {}})
    all_urls = defaultdict(lambda: {'source_files': set(), 'enrichment': {}})
    all_emails = defaultdict(lambda: {'source_files': set(), 'enrichment': {}})
    all_email_data = {}
    
    # NEW: Dictionaries for generic IOCs
    all_generic_ips = defaultdict(lambda: {'source_files': set(), 'enrichment': {}})
    all_generic_domains = defaultdict(lambda: {'source_files': set(), 'enrichment': {}})
    all_generic_urls = defaultdict(lambda: {'source_files': set(), 'enrichment': {}})

    try:
        all_files = get_files_from_path(file_path)
    except ValueError as e: 
        tqdm.write(f"{color.ERROR}[✗] {e}{color.END}")
        return None, None, None, None, None, None, None, None, None
    if not all_files:
        tqdm.write(f"{color.WARNING}[!] No supported files found in the specified path. Exiting.{color.END}")
        return None, None, None, None, None, None, None, None, None
    
    for f in tqdm(all_files, desc=f"{color.INFO}Extracting IOCs from Files{color.END}", unit="file", ncols=80, leave=False):
        file_extension = os.path.splitext(f)[1].lower()
        
        file_ips, file_hashes, file_domains, file_urls, file_emails_dict, file_msg_ids, extracted_pcap_files = extract_iocs_from_file(f, scan_attachments)
        
        # Merge extracted IOCs into the main dictionaries using sets for efficient deduplication
        for ioc in file_ips:
            if is_generic_ioc(ioc, "IP"):
                all_generic_ips[ioc]['source_files'].add(f)
            else:
                all_ips[ioc]['source_files'].add(f)
                
        for h_dict in file_hashes:
            # Hashes are never generic, so no change needed here
            all_hashes[h_dict['hash']]['source_files'].add(h_dict['source_file'])
            all_hashes[h_dict['hash']]['hash_type'] = h_dict.get('type', 'Unknown')
        
        for ioc in file_domains:
            if is_generic_ioc(ioc, "Domain"):
                all_generic_domains[ioc]['source_files'].add(f)
            else:
                all_domains[ioc]['source_files'].add(f)
                
        for ioc in file_urls:
            if is_generic_ioc(ioc, "URL"):
                all_generic_urls[ioc]['source_files'].add(f)
            else:
                all_urls[ioc]['source_files'].add(f)
                
        for ioc, msg_id in file_emails_dict.items():
            # Emails are never generic, so no change needed here
            all_emails[ioc]['source_files'].add(f)
            all_email_data[ioc] = msg_id
            
        # Add hashes for any files extracted from the PCAP to the main hash dictionary
        for h_dict in [h for f in extracted_pcap_files for h in hash_file(f)]:
            all_hashes[h_dict['hash']]['source_files'].add(h_dict['source_file'])
            all_hashes[h_dict['hash']]['hash_type'] = h_dict.get('type', 'Unknown')
            
    print(f"\n{color.SUCCESS}[✓] Extraction complete.{color.END}")
    return all_ips, all_hashes, all_domains, all_urls, all_emails, all_email_data, all_generic_ips, all_generic_domains, all_generic_urls

def enrich_iocs(all_ips, all_hashes, all_domains, all_urls, all_generic_ips, all_generic_domains, all_generic_urls, abuse_key, vt_key):
    """Orchestrates the IOC enrichment process, only asking for types with a valid key."""
    
    enricher = Enricher(abuse_key, vt_key)
    
    tqdm.write(f"\n{color.INFO}[*] Starting Enrichment of Unique IOCs...{color.END}")
    
    if abuse_key:
        enrich_ip_flag = input("Enrich IPs? [Y/n]: ").strip().lower() not in ('n','no')
    else:
        print(f"{color.WARNING}[!] Skipping IP enrichment. AbuseIPDB API key not found.{color.END}")
        enrich_ip_flag = False
    
    if vt_key:
        enrich_hash_flag = input("Enrich Hashes? [Y/n]: ").strip().lower() not in ('n','no')
        enrich_domain_flag = input("Enrich Domains? [Y/n]: ").strip().lower() not in ('n','no')
        enrich_url_flag = input("Enrich URLs? [Y/n]: ").strip().lower() not in ('n','no')
    else:
        print(f"{color.WARNING}[!] Skipping Hash, Domain, and URL enrichment. VirusTotal API key not found.{color.END}")
        enrich_hash_flag = False
        enrich_domain_flag = False
        enrich_url_flag = False
        
    enrich_generic_flag = False
    if abuse_key or vt_key:
        enrich_generic_flag = input("Enrich generic IOCs (e.g., from Google, AWS)? [y/N]: ").strip().lower() in ('y','yes')

    if enrich_ip_flag and all_ips:
        for ioc in tqdm(all_ips, desc=f"  Enriching {len(all_ips)} unique IPs", ncols=80, leave=False):
            all_ips[ioc]['enrichment'] = enricher.enrich_ip(ioc)
        print(f"{color.SUCCESS}[✓] IP enrichment complete.{color.END}")
        
    if enrich_generic_flag and enrich_ip_flag and all_generic_ips:
        for ioc in tqdm(all_generic_ips, desc=f"  Enriching {len(all_generic_ips)} generic IPs", ncols=80, leave=False):
            all_generic_ips[ioc]['enrichment'] = enricher.enrich_ip(ioc)
        print(f"{color.SUCCESS}[✓] Generic IP enrichment complete.{color.END}")
    
    if enrich_hash_flag and all_hashes:
        for ioc in tqdm(all_hashes, desc=f"  Enriching {len(all_hashes)} unique Hashes", ncols=80, leave=False):
            all_hashes[ioc]['enrichment'] = enricher.enrich_hash(ioc)
        print(f"{color.SUCCESS}[✓] Hash enrichment complete.{color.END}")
    
    if enrich_domain_flag and all_domains:
        for ioc in tqdm(all_domains, desc=f"  Enriching {len(all_domains)} unique Domains", ncols=80, leave=False):
            all_domains[ioc]['enrichment'] = enricher.enrich_domain(ioc)
        print(f"{color.SUCCESS}[✓] Domain enrichment complete.{color.END}")
        
    if enrich_generic_flag and enrich_domain_flag and all_generic_domains:
        for ioc in tqdm(all_generic_domains, desc=f"  Enriching {len(all_generic_domains)} generic Domains", ncols=80, leave=False):
            all_generic_domains[ioc]['enrichment'] = enricher.enrich_domain(ioc)
        print(f"{color.SUCCESS}[✓] Generic Domain enrichment complete.{color.END}")
    
    if enrich_url_flag and all_urls:
        for ioc in tqdm(all_urls, desc=f"  Enriching {len(all_urls)} unique URLs", ncols=80, leave=False):
            all_urls[ioc]['enrichment'] = enricher.enrich_url(ioc)
        print(f"{color.SUCCESS}[✓] URL enrichment complete.{color.END}")
        
    if enrich_generic_flag and enrich_url_flag and all_generic_urls:
        for ioc in tqdm(all_generic_urls, desc=f"  Enriching {len(all_generic_urls)} generic URLs", ncols=80, leave=False):
            all_generic_urls[ioc]['enrichment'] = enricher.enrich_url(ioc)
        print(f"{color.SUCCESS}[✓] Generic URL enrichment complete.{color.END}")
        
    return all_ips, all_hashes, all_domains, all_urls, all_generic_ips, all_generic_domains, all_generic_urls

def main_menu():
    """Main menu and script orchestration."""
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r"""
  ____ ____      _    ____ ___ ______   __
 / ___|  _ \    / \  | __ )_ _|  _ \ \ / /
| | _ | |_) |  / _ \ |  _ \| || |_) \ V / 
| |_| |  _ <  / ___ \| |_) | ||  __/ | | 
 \____|_| \_\/_/   \_\____/___|_|    |_| 
  
      Threat Intel & Enrichment Tool
            Created by Blu3J4x
"""
    print(f"{color.INFO}{banner}{color.END}")
    print(f"{color.INFO}This tool automatically scans files and folders to extract Indicators of Compromise (IOCs)\n"
          "including IPs, hashes (MD5, SHA1, SHA256), domains, URLs, and email addresses.\n"
          "\n"
          "Features:\n"
          "- Wide File Support: Processes .txt, .csv, .xlsx, .docx, .pdf, .msg, .eml, and .pcap files.\n"
          "- Automated Enrichment: Optionally enriches collected IOCs against threat intelligence services\n"
          "  like AbuseIPDB and VirusTotal to provide valuable context and risk scoring.\n"
          "- Advanced Parsing: Extracts email headers, Message-IDs, and automatically reconstructs\n"
          "  and saves files transferred over unencrypted HTTP connections in PCAP files.\n"
          "- Enhanced Usability: Streamlined workflow with an interactive menu, secure API key storage\n"
          "  in a separate 'config.ini' file, and efficient, memory-safe file handling.\n"
          "- Comprehensive Output: Generates a timestamped CSV report with all extracted IOCs,\n"
          "  and enrichment data.\n"
          "- Defanging Capability: Offers the option to defang the output, replacing periods with [.] and http/https\n"
          "  with hxxp/hxxps to prevent accidental clicks. {color.END}\n")
    
    
    while True:
        print("\n--- Main Menu ---")
        print("1. Run IOC Extraction & Enrichment")
        print("2. Set up/update API keys")
        print("3. Exit")
        
        choice = input(f"{color.INFO}Enter your choice (1-3): {color.END}").strip()
        
        if choice == '1':
            
            # Initialize all IOC containers to be empty to prevent errors
            all_ips, all_hashes, all_domains, all_urls, all_emails, all_email_data, all_generic_ips, all_generic_domains, all_generic_urls = [], {}, {}, {}, {}, {}, [], [], []

            file_path = input("Enter the file/folder path containing IOCs (default: current folder): ").strip() or "."
            scan_attachments = input("Scan email attachments? [y/N]: ").strip().lower() in ('y','yes')
            
            all_ips, all_hashes, all_domains, all_urls, all_emails, all_email_data, all_generic_ips, all_generic_domains, all_generic_urls = extract_iocs(file_path, scan_attachments)

            if all_ips or all_hashes or all_domains or all_urls or all_emails or all_generic_ips or all_generic_domains or all_generic_urls:
                enrich_choice = input(f"\nExtraction complete. Would you like to proceed with enrichment? [Y/n]: ").strip().lower()
                
                if enrich_choice not in ('n', 'no'):
                    # This new loop will check for keys and prompt the user if they are missing
                    keys_loaded = False
                    while True:
                        abuse_key, vt_key = load_config()
                        if abuse_key or vt_key:
                            keys_loaded = True
                            break # Exit loop if keys are found

                        # If keys are not found, prompt the user
                        print(f"{color.WARNING}[!] No API keys found.{color.END}")
                        setup_now = input("Would you like to set up API keys now? [Y/n]: ").strip().lower()
                        
                        if setup_now in ('', 'y', 'yes'):
                            setup_config() # Run the setup, then the loop will try again
                        else:
                            print(f"{color.INFO}[*] Skipping enrichment.{color.END}")
                            break # Exit loop if user says no

                    # After the loop, only enrich if keys were successfully loaded
                    if keys_loaded:
                        try:
                            all_ips, all_hashes, all_domains, all_urls, all_generic_ips, all_generic_domains, all_generic_urls = enrich_iocs(
                                all_ips, all_hashes, all_domains, all_urls, all_generic_ips, all_generic_domains, all_generic_urls, abuse_key, vt_key)
                        except KeyboardInterrupt:
                            tqdm.write(f"\n{color.WARNING}[!] Enrichment interrupted by user (Ctrl+C). Writing collected data to CSV...{color.END}")
                else:
                    tqdm.write(f"\n{color.INFO}[*] Skipping enrichment. Writing extracted IOCs to CSV...{color.END}")
            else:
                print(f"{color.WARNING}[!] No IOCs found. Exiting.{color.END}")
                break
                
            defang_output_flag = input("\nWould you like to defang the output (IPs, Domains, and URLs)? [y/N]: ").strip().lower() in ('y','yes')
            segregate_generic_flag = input("Segregate generic IOCs into a separate section in the report? [Y/n]: ").strip().lower() not in ('n', 'no')
            
            # --- Stage 3: CSV Output ---
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file=f"ioc_enriched_report_{timestamp}.csv"
            
            try:
                with open(output_file,'w',newline='',encoding='utf-8') as f:
                    writer = csv.writer(f)
                    
                    # Sort IOCs by their risk level
                    sorted_ips = sorted(all_ips.items(), key=lambda item: item[1]['enrichment'].get('Abuse Score', -1), reverse=True)
                    sorted_generic_ips = sorted(all_generic_ips.items(), key=lambda item: item[1]['enrichment'].get('Abuse Score', -1), reverse=True)
                    sorted_hashes = sorted(all_hashes.items(), key=lambda item: item[1]['enrichment'].get('Malicious', -1), reverse=True)
                    sorted_domains = sorted(all_domains.items(), key=lambda item: item[1]['enrichment'].get('Malicious', -1), reverse=True)
                    sorted_generic_domains = sorted(all_generic_domains.items(), key=lambda item: item[1]['enrichment'].get('Malicious', -1), reverse=True)
                    sorted_urls = sorted(all_urls.items(), key=lambda item: item[1]['enrichment'].get('Malicious', -1), reverse=True)
                    sorted_generic_urls = sorted(all_generic_urls.items(), key=lambda item: item[1]['enrichment'].get('Malicious', -1), reverse=True)

                    # Separate hashes with detections or errors
                    hashes_with_issues = {k: v for k, v in sorted_hashes if v['enrichment'].get('Malicious', 0) > 0 or v['enrichment'].get('Error')}
                    hashes_no_issues = {k: v for k, v in sorted_hashes if not (v['enrichment'].get('Malicious', 0) > 0 or v['enrichment'].get('Error'))}
                    
                    if sorted_ips or (not segregate_generic_flag and sorted_generic_ips):
                        combined_ips = sorted_ips + sorted_generic_ips if not segregate_generic_flag else sorted_ips
                        writer.writerow([''])
                        writer.writerow(['IP IOCs', 'Data'])
                        writer.writerow(['IOC','Type','Abuse Score','Risk Level','Country','ISP','Domain','Hostname(s)','Last Reported','Source File(s)','Error'])
                        for ioc, data in combined_ips:
                            ioc_to_write = defang('IP', ioc) if defang_output_flag else ioc
                            writer.writerow([
                                ioc_to_write, 'IP',
                                data['enrichment'].get('Abuse Score', ''),
                                data['enrichment'].get('Risk Level', ''),
                                data['enrichment'].get('Country', ''),
                                data['enrichment'].get('ISP', ''),
                                data['enrichment'].get('Domain', ''),
                                data['enrichment'].get('Hostname(s)', ''),
                                data['enrichment'].get('Last Reported', ''),
                                " | ".join(sorted(list(set(data['source_files'])))),
                                data['enrichment'].get('Error', '')
                            ])
                            
                    if segregate_generic_flag and sorted_generic_ips:
                        writer.writerow([''])
                        writer.writerow(['Generic IP IOCs', 'Data'])
                        writer.writerow(['IOC','Type','Abuse Score','Risk Level','Country','ISP','Domain','Hostname(s)','Last Reported','Source File(s)','Error'])
                        for ioc, data in sorted_generic_ips:
                            ioc_to_write = defang('IP', ioc) if defang_output_flag else ioc
                            writer.writerow([
                                ioc_to_write, 'IP',
                                data['enrichment'].get('Abuse Score', ''),
                                data['enrichment'].get('Risk Level', ''),
                                data['enrichment'].get('Country', ''),
                                data['enrichment'].get('ISP', ''),
                                data['enrichment'].get('Domain', ''),
                                data['enrichment'].get('Hostname(s)', ''),
                                data['enrichment'].get('Last Reported', ''),
                                " | ".join(sorted(list(set(data['source_files'])))),
                                data['enrichment'].get('Error', '')
                            ])

                    if hashes_with_issues:
                        writer.writerow([''])
                        writer.writerow(['Hash IOCs with Detections or Errors', 'Data'])
                        writer.writerow(['IOC','Hash Type','Type','Detection Ratio','Harmless','Malicious','Suspicious','Undetected','Type Description','First Seen','Last Seen','Tags','Source File(s)','Error'])
                        for ioc, data in hashes_with_issues.items():
                            writer.writerow([
                                ioc,
                                data.get('hash_type', ''),
                                'Hash',
                                data['enrichment'].get('Detection Ratio', ''),
                                data['enrichment'].get('Harmless', ''),
                                data['enrichment'].get('Malicious', ''),
                                data['enrichment'].get('Suspicious', ''),
                                data['enrichment'].get('Undetected', ''),
                                data['enrichment'].get('Type Description', ''),
                                data['enrichment'].get('First Seen', ''),
                                data['enrichment'].get('Last Seen', ''),
                                data['enrichment'].get('Tags', ''),
                                " | ".join(sorted(list(data['source_files']))),
                                data['enrichment'].get('Error', '')
                            ])
                            
                    if hashes_no_issues:
                        writer.writerow([''])
                        writer.writerow(['Harmless Hash IOCs', 'Data'])
                        writer.writerow(['IOC','Hash Type','Type','Detection Ratio','Harmless','Malicious','Suspicious','Undetected','Type Description','First Seen','Last Seen','Tags','Source File(s)','Error'])
                        for ioc, data in hashes_no_issues.items():
                            writer.writerow([
                                ioc,
                                data.get('hash_type', ''),
                                'Hash',
                                data['enrichment'].get('Detection Ratio', ''),
                                data['enrichment'].get('Harmless', ''),
                                data['enrichment'].get('Malicious', ''),
                                data['enrichment'].get('Suspicious', ''),
                                data['enrichment'].get('Undetected', ''),
                                data['enrichment'].get('Type Description', ''),
                                data['enrichment'].get('First Seen', ''),
                                data['enrichment'].get('Last Seen', ''),
                                data['enrichment'].get('Tags', ''),
                                " | ".join(sorted(list(data['source_files']))),
                                data['enrichment'].get('Error', '')
                            ])
                    
                    if sorted_domains or (not segregate_generic_flag and sorted_generic_domains):
                        combined_domains = sorted_domains + sorted_generic_domains if not segregate_generic_flag else sorted_domains
                        writer.writerow([''])
                        writer.writerow(['Domain IOCs', 'Data'])
                        writer.writerow(['IOC','Type','Risk Level','Malicious','Harmless','Suspicious','Undetected','Notes','Source File(s)','Error'])
                        for ioc, data in combined_domains:
                            ioc_to_write = defang('Domain', ioc) if defang_output_flag else ioc
                            writer.writerow([
                                ioc_to_write, 'Domain',
                                data['enrichment'].get('Risk Level', ''),
                                data['enrichment'].get('Malicious', ''),
                                data['enrichment'].get('Harmless', ''),
                                data['enrichment'].get('Suspicious', ''),
                                data['enrichment'].get('Undetected', ''),
                                data['enrichment'].get('Notes', ''),
                                " | ".join(sorted(list(data['source_files']))),
                                data['enrichment'].get('Error', '')
                            ])

                    if segregate_generic_flag and sorted_generic_domains:
                        writer.writerow([''])
                        writer.writerow(['Generic Domain IOCs', 'Data'])
                        writer.writerow(['IOC','Type','Risk Level','Malicious','Harmless','Suspicious','Undetected','Notes','Source File(s)','Error'])
                        for ioc, data in sorted_generic_domains:
                            ioc_to_write = defang('Domain', ioc) if defang_output_flag else ioc
                            writer.writerow([
                                ioc_to_write, 'Domain',
                                data['enrichment'].get('Risk Level', ''),
                                data['enrichment'].get('Malicious', ''),
                                data['enrichment'].get('Harmless', ''),
                                data['enrichment'].get('Suspicious', ''),
                                data['enrichment'].get('Undetected', ''),
                                data['enrichment'].get('Notes', ''),
                                " | ".join(sorted(list(data['source_files']))),
                                data['enrichment'].get('Error', '')
                            ])

                    if sorted_urls or (not segregate_generic_flag and sorted_generic_urls):
                        combined_urls = sorted_urls + sorted_generic_urls if not segregate_generic_flag else sorted_urls
                        writer.writerow([''])
                        writer.writerow(['URL IOCs', 'Data'])
                        writer.writerow(['IOC','Type','Risk Level','Malicious','Harmless','Suspicious','Undetected','Notes','Source File(s)','Error'])
                        for ioc, data in combined_urls:
                            ioc_to_write = defang('URL', ioc) if defang_output_flag else ioc
                            writer.writerow([
                                ioc_to_write, 'URL',
                                data['enrichment'].get('Risk Level', ''),
                                data['enrichment'].get('Malicious', ''),
                                data['enrichment'].get('Harmless', ''),
                                data['enrichment'].get('Suspicious', ''),
                                data['enrichment'].get('Undetected', ''),
                                data['enrichment'].get('Notes', ''),
                                " | ".join(sorted(list(data['source_files']))),
                                data['enrichment'].get('Error', '')
                            ])
                    
                    if segregate_generic_flag and sorted_generic_urls:
                        writer.writerow([''])
                        writer.writerow(['Generic URL IOCs', 'Data'])
                        writer.writerow(['IOC','Type','Risk Level','Malicious','Harmless','Suspicious','Undetected','Notes','Source File(s)','Error'])
                        for ioc, data in sorted_generic_urls:
                            ioc_to_write = defang('URL', ioc) if defang_output_flag else ioc
                            writer.writerow([
                                ioc_to_write, 'URL',
                                data['enrichment'].get('Risk Level', ''),
                                data['enrichment'].get('Malicious', ''),
                                data['enrichment'].get('Harmless', ''),
                                data['enrichment'].get('Suspicious', ''),
                                data['enrichment'].get('Undetected', ''),
                                data['enrichment'].get('Notes', ''),
                                " | ".join(sorted(list(data['source_files']))),
                                data['enrichment'].get('Error', '')
                            ])

                    if all_emails:
                        writer.writerow([''])
                        writer.writerow(['Email IOCs', 'Data'])
                        writer.writerow(['IOC','Root Domain','Message-ID','Type','Source File(s)','Error'])
                        for ioc, data in all_emails.items():
                            writer.writerow([
                                ioc,
                                get_root_domain(ioc),
                                clean_message_id(all_email_data.get(ioc, '')),
                                'Email',
                                " | ".join(sorted(list(data['source_files']))),
                                data['enrichment'].get('Error', '')
                            ])

                tqdm.write(f"\n{color.SUCCESS}[✓] All collected results written to {output_file}{color.END}")
                
                ioc_types = []
                if all_ips: ioc_types.extend(['IP'] * len(all_ips))
                if all_hashes: ioc_types.extend(['Hash'] * len(all_hashes))
                if all_domains: ioc_types.extend(['Domain'] * len(all_domains))
                if all_urls: ioc_types.extend(['URL'] * len(all_urls))
                if all_emails: ioc_types.extend(['Email'] * len(all_emails))
                if all_generic_ips: ioc_types.extend(['Generic IP'] * len(all_generic_ips))
                if all_generic_domains: ioc_types.extend(['Generic Domain'] * len(all_generic_domains))
                if all_generic_urls: ioc_types.extend(['Generic URL'] * len(all_generic_urls))

                summary = Counter(ioc_types)

                tqdm.write("\n=== Summary ===")
                for k, v in summary.items():
                    tqdm.write(f"{k}: {v}")
                
                print(f"\n{color.SUCCESS}[✓] All checks completed.{color.END}")
            except Exception as e:
                tqdm.write(f"{color.ERROR}[✗] An error occurred while writing the CSV file: {e}{color.END}")

            break

        elif choice == '2':
            abuse_key, vt_key = setup_config()
            
        elif choice == '3':
            print(f"{color.INFO}Exiting.{color.END}")
            sys.exit(0)
            
        else:
            print(f"{color.ERROR}[✗] Invalid choice. Please enter 1, 2, or 3.{color.END}")

if __name__=="__main__":
    main_menu()
