#!/usr/bin/env python3
"""
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
def check_install(module_name, pip_name=None):
    pip_name = pip_name or module_name
    try: __import__(module_name)
    except ImportError:
        print(f"{color.WARNING}[!] Missing required module: {module_name}{color.END}")
        choice = input(f"Do you want to try installing {pip_name} now? [Y/n]: ").strip().lower()
        if choice in ('', 'y', 'yes'):
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pip_name])
            print(f"{color.SUCCESS}[✓] {pip_name} installed. Please re-run the script.{color.END}\n")
        else:
            print(f"{color.ERROR}[✗] {module_name} is required. Exiting.{color.END}\n")
        sys.exit(1)

dependencies = {
    "docx": "python-docx",
    "pdfplumber": "pdfplumber",
    "extract_msg": "extract-msg",
    "pandas": "pandas",
    "openpyxl": "openpyxl",
    "tqdm": "tqdm",
    "tldextract": "tldextract",
    "bs4": "beautifulsoup4",
    "scapy": "scapy"
}

# Add dependencies that aren't core modules and can be checked
extra_dependencies = ["six", "numpy", "dateutil", "pytz"]
for mod in extra_dependencies:
    check_install(mod)

for mod, pip_name in dependencies.items():
    check_install(mod, pip_name)

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
            with open(file_path, 'r', errors='ignore') as f:
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
def extract_iocs_from_file(file_path, scan_attachments=False):
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

            found_md5 = RE_MD5.findall(item)
            if found_md5:
                hashes.update([(h, 'md5', file_path) for h in found_md5])
            
            found_sha1 = RE_SHA1.findall(item)
            if found_sha1:
                hashes.update([(h, 'sha1', file_path) for h in found_sha1])

            found_sha256 = RE_SHA256.findall(item)
            if found_sha256:
                hashes.update([(h, 'sha256', file_path) for h in found_sha256])

            for e in RE_EMAIL.findall(item):
                ce = clean_email(e)
                emails_dict[ce] = ''
                add_domain_from_string(ce.split('@')[-1])

            for u in RE_URL.findall(item):
                add_url_and_domain(u)

            words = re.split(r'[\s,;<>]+', item)
            for word in words:
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
            risk="High" if malicious_count>0 else "Low"
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
    
    try:
        all_files = get_files_from_path(file_path)
    except ValueError as e: 
        tqdm.write(f"{color.ERROR}[✗] {e}{color.END}")
        return None, None, None, None, None, None
    if not all_files:
        tqdm.write(f"{color.WARNING}[!] No supported files found in the specified path. Exiting.{color.END}")
        return None, None, None, None, None, None
    
    for f in tqdm(all_files, desc=f"{color.INFO}Extracting IOCs from Files{color.END}", unit="file", ncols=80, leave=False):
        file_extension = os.path.splitext(f)[1].lower()
        
        file_ips, file_hashes, file_domains, file_urls, file_emails_dict, file_msg_ids, extracted_pcap_files = extract_iocs_from_file(f, scan_attachments)
        
        # Merge extracted IOCs into the main dictionaries using sets for efficient deduplication
        for ioc in file_ips: all_ips[ioc]['source_files'].add(f)
        for h_dict in file_hashes:
            all_hashes[h_dict['hash']]['source_files'].add(h_dict['source_file'])
            all_hashes[h_dict['hash']]['hash_type'] = h_dict.get('type', 'Unknown')
        for ioc in file_domains: all_domains[ioc]['source_files'].add(f)
        for ioc in file_urls: all_urls[ioc]['source_files'].add(f)
        for ioc, msg_id in file_emails_dict.items():
            all_emails[ioc]['source_files'].add(f)
            all_email_data[ioc] = msg_id
            
        # Add hashes for any files extracted from the PCAP to the main hash dictionary
        for h_dict in [h for f in extracted_pcap_files for h in hash_file(f)]:
            all_hashes[h_dict['hash']]['source_files'].add(h_dict['source_file'])
            all_hashes[h_dict['hash']]['hash_type'] = h_dict.get('type', 'Unknown')
            
    print(f"\n{color.SUCCESS}[✓] Extraction complete.{color.END}")
    return all_ips, all_hashes, all_domains, all_urls, all_emails, all_email_data

def enrich_iocs(all_ips, all_hashes, all_domains, all_urls, abuse_key, vt_key):
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

    if enrich_ip_flag and all_ips:
        for ioc in tqdm(all_ips, desc=f"  Enriching {len(all_ips)} unique IPs", ncols=80, leave=False):
            all_ips[ioc]['enrichment'] = enricher.enrich_ip(ioc)
        print(f"{color.SUCCESS}[✓] IP enrichment complete.{color.END}")
    
    if enrich_hash_flag and all_hashes:
        for ioc in tqdm(all_hashes, desc=f"  Enriching {len(all_hashes)} unique Hashes", ncols=80, leave=False):
            all_hashes[ioc]['enrichment'] = enricher.enrich_hash(ioc)
        print(f"{color.SUCCESS}[✓] Hash enrichment complete.{color.END}")
    
    if enrich_domain_flag and all_domains:
        for ioc in tqdm(all_domains, desc=f"  Enriching {len(all_domains)} unique Domains", ncols=80, leave=False):
            all_domains[ioc]['enrichment'] = enricher.enrich_domain(ioc)
        print(f"{color.SUCCESS}[✓] Domain enrichment complete.{color.END}")
    
    if enrich_url_flag and all_urls:
        for ioc in tqdm(all_urls, desc=f"  Enriching {len(all_urls)} unique URLs", ncols=80, leave=False):
            all_urls[ioc]['enrichment'] = enricher.enrich_url(ioc)
        print(f"{color.SUCCESS}[✓] URL enrichment complete.{color.END}")
        
    return all_ips, all_hashes, all_domains, all_urls

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
          "  and enrichment data.{color.END}\n")
    
    
    while True:
        print("\n--- Main Menu ---")
        print("1. Run IOC Extraction & Enrichment")
        print("2. Set up/update API keys")
        print("3. Exit")
        
        choice = input(f"{color.INFO}Enter your choice (1-3): {color.END}").strip()
        
        if choice == '1':
            
            file_path = input("Enter the file/folder path containing IOCs (default: current folder): ").strip() or "."
            scan_attachments = input("Scan email attachments? [y/N]: ").strip().lower() in ('y','yes')
            
            all_ips, all_hashes, all_domains, all_urls, all_emails, all_email_data = extract_iocs(file_path, scan_attachments)

            if all_ips or all_hashes or all_domains or all_urls or all_emails:
                enrich_choice = input(f"\nExtraction complete. Would you like to proceed with enrichment? [Y/n]: ").strip().lower()
                if enrich_choice not in ('n', 'no'):
                    abuse_key, vt_key = load_config()
                    if not abuse_key and not vt_key:
                        print(f"{color.WARNING}[!] No API keys found. Skipping all enrichment.{color.END}")
                    else:
                        try:
                            all_ips, all_hashes, all_domains, all_urls = enrich_iocs(all_ips, all_hashes, all_domains, all_urls, abuse_key, vt_key)
                        except KeyboardInterrupt:
                            tqdm.write(f"\n{color.WARNING}[!] Enrichment interrupted by user (Ctrl+C). Writing collected data to CSV...{color.END}")
                else:
                    tqdm.write(f"\n{color.INFO}[*] Skipping enrichment. Writing extracted IOCs to CSV...{color.END}")
            else:
                print(f"{color.WARNING}[!] No IOCs found. Exiting.{color.END}")
                break
                
            defang_output_flag = input("\nWould you like to defang the output (IPs, Domains, and URLs)? [y/N]: ").strip().lower() in ('y','yes')

            # --- Stage 3: CSV Output ---
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file=f"ioc_enriched_report_{timestamp}.csv"
            
            try:
                with open(output_file,'w',newline='',encoding='utf-8') as f:
                    writer = csv.writer(f)
                    
                    if all_ips:
                        writer.writerow([''])
                        writer.writerow(['IP IOCs', 'Data'])
                        writer.writerow(['IOC','Type','Abuse Score','Risk Level','Country','ISP','Domain','Hostname(s)','Last Reported','Source File(s)','Error'])
                        for ioc, data in all_ips.items():
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

                    if all_hashes:
                        writer.writerow([''])
                        writer.writerow(['Hash IOCs', 'Data'])
                        writer.writerow(['IOC','Hash Type','Type','Detection Ratio','Harmless','Malicious','Suspicious','Undetected','Type Description','First Seen','Last Seen','Tags','Source File(s)','Error'])
                        for ioc, data in all_hashes.items():
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
                    
                    if all_domains:
                        writer.writerow([''])
                        writer.writerow(['Domain IOCs', 'Data'])
                        writer.writerow(['IOC','Type','Risk Level','Malicious','Harmless','Suspicious','Undetected','Notes','Source File(s)','Error'])
                        for ioc, data in all_domains.items():
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

                    if all_urls:
                        writer.writerow([''])
                        writer.writerow(['URL IOCs', 'Data'])
                        writer.writerow(['IOC','Type','Risk Level','Malicious','Harmless','Suspicious','Undetected','Notes','Source File(s)','Error'])
                        for ioc, data in all_urls.items():
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
