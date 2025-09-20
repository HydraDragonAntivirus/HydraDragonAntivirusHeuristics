#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HydraScanner - Hardcoded Obfuscation Detection (patched + RAPPS installer adjustment)
This variant adds:
 - RAPPS Downloads auto-whitelist (configurable)
 - Probable-installer heuristic with configurable score deduction (default -20)
 - GUI toggles for RAPPS whitelist and installer deduction
 - Persistent config file: scanner_config.json
 - Simple audit stats persisted in scanner_stats.json
 - Logging of adjustments for scientific measurement and tuning
Compatible with Python 3.5+ and typical Windows dev environments.

Additional integrated features (kept and merged into the original file):
 - Script/text obfuscation scoring for common script types (JS/PS1/PY/VBS/etc.)
   - scripts now get "HEUR:Script.Obfuscated" / HEUR:Script.Clean" detections instead of being skipped
 - Last scan duration and cumulative scan time persisted in scanner_stats.json
 - scan_directory_parallel reports elapsed time to the UI and stats
 - RAPPS whitelist path-checking corrected to use absolute-folder matching
"""
import os
import math
import time
import json
import threading
import datetime
import hydra_logger
import quarantine
import re
import string
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import ctypes
import psutil

# --- Compatibility imports for tkinter ---
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext, messagebox
except ImportError:
    import Tkinter as tk
    import ttk
    import tkFileDialog as filedialog
    import ScrolledText as scrolledtext
    import tkMessageBox as messagebox

# Import the PE feature extractor helper (kept per requirement)
try:
    from pe_feature_extractor import get_cached_pe_features
except ImportError:
    hydra_logger.logger.error("Could not import PE feature extractor. Make sure pe_feature_extractor.py is available.")
    raise

base_dir = os.path.dirname(os.path.abspath(__file__))

# --- Provide STARTUP_DIRS default if not defined elsewhere ---
# (Some helper functions reference STARTUP_DIRS; keep safe)
STARTUP_DIRS = [
    os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup') if os.environ.get('APPDATA') else ''
]

# --- Persistence files ---
_SCAN_HISTORY_FILE = os.path.join(base_dir, "scan_history.json")
_KNOWN_MALWARE_FILE = os.path.join(base_dir, "known_malware.json")
_persistence_lock = threading.RLock()

# --- New config and stats files ---
_CONFIG_FILE = os.path.join(base_dir, "scanner_config.json")
_STATS_FILE = os.path.join(base_dir, "scanner_stats.json")

# --- Globals and Configuration (defaults) ---
SUSPICIOUS_THRESHOLD = 47  # original default
DETECTION_NAME = "HEUR:Win32.Susp.Obfuscated.gen"

SUSPICIOUS_DIRS = [
    os.environ.get('TEMP', ''),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads') if os.environ.get('USERPROFILE') else '',
    os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp') if os.environ.get('USERPROFILE') else ''
]

# Bind SHGetFolderPathW
SHGetFolderPathW = ctypes.windll.shell32.SHGetFolderPathW

# Constants
CSIDL_PERSONAL = 0x0005  # "My Documents"
MAX_PATH = 260

def get_documents_folder():
    """Get 'My Documents' folder (works on XP, ReactOS)."""
    path_buf = ctypes.create_unicode_buffer(MAX_PATH)
    hr = SHGetFolderPathW(0, CSIDL_PERSONAL, 0, 0, path_buf)
    if hr != 0:
        # fallback if API fails
        return Path(os.environ.get("USERPROFILE", "")) / "Documents"
    return Path(path_buf.value)
    
docs = get_documents_folder()
rapps_folder = docs / "RAPPS Downloads"

ENABLE_RAPPS_WHITELIST = True  # keep the toggle

def is_rapps_whitelisted(path):
    """
    Check if the given path is inside any of the known RAPPS folders.
    """
    try:
        if not path:
            return False
        path_norm = os.path.abspath(path).lower()
        if rapps_folder:
            folder_abs = os.path.abspath(rapps_folder)
            # exact folder equality or path inside that folder
            if folder_abs == path_norm or path_norm.startswith(folder_abs + os.sep):
                return True
    except Exception as e:
        hydra_logger.logger.debug("RAPPS whitelist check failed for {}: {}".format(path, e), exc_info=True)
    return False

# Default scanner config (can be changed in scanner_config.json)
_DEFAULT_CONFIG = {
    "enable_browser_session_data_detection": True,
    "detect_browser_data": True,                     # enable browser-specific DB detection (Chromium/Firefox)
    "database_detection_mode": "suppress_longline",  # "suppress_longline" (recommended) or "skip_all"
    "database_detection_confidence": 0.65,           # weighted-confidence threshold (0.0 - 1.0)

    "enable_rapps_whitelist": True,
    "enable_installer_adjustment": True,
    "installer_score_deduction": 20,  # points to deduct when installer heuristics match
    "suspicious_threshold": SUSPICIOUS_THRESHOLD,
    "script_suspicious_threshold": 50,
    "audit_log_enabled": True,
    "audit_log_file": os.path.join(base_dir, "scanner_audit.log")
}

def is_legitimate_browser_session_data(content):
    """
    Detect legitimate browser session data to prevent false positive malware detection.
    Returns (is_browser_data: bool, browser_type: str or None, confidence_reason: str or None).
    """
    try:
        content = content.strip()
        
        # Must be JSON-like structure
        if not (content.startswith('{') or content.startswith('[')):
            return False, None, None
        
        # Try to parse JSON
        try:
            data = json.loads(content)
        except ValueError:  # JSONDecodeError is not in Python 3.5
            return False, None, None
        
        if not isinstance(data, dict):
            return False, None, None
        
        confidence_reasons = []
        browser_type = None
        
        # Firefox session detection
        firefox_session_keys = {"windows", "selectedWindow", "_closedWindows", "session", "scratchpads"}
        if len(firefox_session_keys.intersection(data.keys())) >= 2:
            browser_type = "firefox"
            confidence_reasons.append("Firefox session structure detected")
            
            if "windows" in data and isinstance(data["windows"], list):
                for window in data["windows"][:1]:
                    if isinstance(window, dict) and "tabs" in window:
                        tabs = window["tabs"]
                        if isinstance(tabs, list) and tabs:
                            first_tab = tabs[0]
                            if isinstance(first_tab, dict) and "entries" in first_tab:
                                entries = first_tab["entries"]
                                if isinstance(entries, list) and entries:
                                    entry = entries[0]
                                    if isinstance(entry, dict) and "url" in entry and "ID" in entry:
                                        confidence_reasons.append("Firefox tab/entry structure confirmed")
            
            if "session" in data and isinstance(data["session"], dict):
                session_data = data["session"]
                if any(key in session_data for key in ["state", "lastUpdate", "startTime"]):
                    confidence_reasons.append("Firefox session metadata present")
        
        # Chrome/Chromium session detection
        chrome_session_keys = {"version", "sessions", "windows", "window"}
        if len(chrome_session_keys.intersection(data.keys())) >= 1:
            if "sessions" in data or ("windows" in data and "version" in data):
                browser_type = "chromium"
                confidence_reasons.append("Chrome/Chromium session structure detected")
        
        # Generic browser session indicators
        browser_indicators = []
        
        # Check for URL patterns in the data
        def find_browser_urls(obj, depth=0):
            if depth > 5:
                return []
            
            urls = []
            if isinstance(obj, dict):
                if "url" in obj and isinstance(obj["url"], str):
                    url = obj["url"]
                    if url.startswith(("http://", "https://", "ftp://", "file://")):
                        urls.append(url)
                
                for value in obj.values():
                    urls.extend(find_browser_urls(value, depth + 1))
                    
            elif isinstance(obj, list):
                for item in obj:
                    urls.extend(find_browser_urls(item, depth + 1))
            
            return urls
        
        urls = find_browser_urls(data)
        if len(urls) >= 1:
            browser_indicators.append("Contains {} valid URLs".format(len(urls)))
            
            domains = set()
            for url in urls:
                try:
                    domain = url.split('/')[2].lower()
                    domains.add(domain)
                except:
                    pass
            
            common_domains = {
                'github.com', 'google.com', 'duckduckgo.com', 'stackoverflow.com',
                'mozilla.org', 'firefox.com', 'microsoft.com', 'apple.com',
                'youtube.com', 'wikipedia.org', 'reddit.com', 'twitter.com',
                'facebook.com', 'linkedin.com', 'virustotal.com'
            }
            
            legitimate_domains = domains.intersection(common_domains)
            if legitimate_domains:
                browser_indicators.append("Contains legitimate domains: {}".format(
                    ', '.join(list(legitimate_domains)[:3])
                ))
        
        # Check for browser-specific field patterns
        browser_fields = {
            "docshellID", "triggeringPrincipal_b64", "structuredCloneState",
            "referrer", "docIdentifier", "lastAccessed", "hidden",
            "cookies", "selectedWindow", "busy", "width", "height", "screenX", "screenY"
        }
        
        found_fields = set()
        def find_browser_fields(obj, depth=0):
            if depth > 3:
                return
            
            if isinstance(obj, dict):
                for key in obj.keys():
                    if key in browser_fields:
                        found_fields.add(key)
                
                for value in obj.values():
                    find_browser_fields(value, depth + 1)
                    
            elif isinstance(obj, list):
                for item in obj:
                    find_browser_fields(item, depth + 1)
        
        find_browser_fields(data)
        if found_fields:
            browser_indicators.append("Browser-specific fields: {}".format(
                ', '.join(list(found_fields)[:3])
            ))
        
        # Check for browser cookies structure
        def check_cookies(obj):
            if isinstance(obj, dict):
                if "cookies" in obj and isinstance(obj["cookies"], list):
                    cookies = obj["cookies"]
                    if cookies and isinstance(cookies[0], dict):
                        cookie = cookies[0]
                        cookie_fields = {"host", "name", "value", "path", "secure", "httponly"}
                        if len(cookie_fields.intersection(cookie.keys())) >= 3:
                            return True
                
                for value in obj.values():
                    if check_cookies(value):
                        return True
            elif isinstance(obj, list):
                for item in obj:
                    if check_cookies(item):
                        return True
            return False
        
        if check_cookies(data):
            browser_indicators.append("Browser cookie structure detected")
        
        confidence_reasons.extend(browser_indicators)
        
        # Decision logic
        is_browser_data = False
        final_reason = None
        
        if browser_type:
            is_browser_data = True
            final_reason = "{} browser session data: {}".format(browser_type.title(), '; '.join(confidence_reasons))
        elif len(browser_indicators) >= 2:
            is_browser_data = True
            browser_type = "generic_browser"
            final_reason = "Generic browser session data: {}".format('; '.join(confidence_reasons))
        elif len(urls) >= 3 and len(found_fields) >= 1:
            is_browser_data = True
            browser_type = "browser_session"
            final_reason = "Browser session data: {}".format('; '.join(confidence_reasons))
        
        return is_browser_data, browser_type, final_reason
        
    except Exception as e:
        return False, None, "Analysis error: {}".format(str(e))

# Attempt to load config, otherwise save defaults
def load_config():
    try:
        with _persistence_lock:
            if os.path.exists(_CONFIG_FILE):
                with open(_CONFIG_FILE, "r", encoding="utf-8") as fh:
                    cfg = json.load(fh)
                    # merge missing keys from defaults
                    merged = dict(_DEFAULT_CONFIG)
                    merged.update(cfg or {})
                    return merged
            else:
                # create default config file
                with open(_CONFIG_FILE, "w", encoding="utf-8") as fh:
                    json.dump(_DEFAULT_CONFIG, fh, ensure_ascii=False, indent=2)
                return dict(_DEFAULT_CONFIG)
    except Exception as e:
        hydra_logger.logger.warning("Failed to load config, using defaults: {}".format(e))
        return dict(_DEFAULT_CONFIG)

CONFIG = load_config()
# Use config values for threshold and other runtime behavior
SUSPICIOUS_THRESHOLD = CONFIG.get("suspicious_threshold", SUSPICIOUS_THRESHOLD)
ENABLE_RAPPS_WHITELIST = bool(CONFIG.get("enable_rapps_whitelist", True))
ENABLE_INSTALLER_ADJUSTMENT = bool(CONFIG.get("enable_installer_adjustment", True))
INSTALLER_SCORE_DEDUCTION = float(CONFIG.get("installer_score_deduction", 20.0))
SCRIPT_SUSPICIOUS_THRESHOLD = float(CONFIG.get("script_suspicious_threshold", 15.0))
AUDIT_LOG_ENABLED = bool(CONFIG.get("audit_log_enabled", True))
AUDIT_LOG_FILE = CONFIG.get("audit_log_file", os.path.join(base_dir, "scanner_audit.log"))

# --- Stats persistence (simple counters) ---
_default_stats = {
    "total_scanned": 0,
    "total_detections": 0,
    "rapps_whitelisted": 0,
    "installer_adjustments_applied": 0,
    "detections_prevented_by_adjustment": 0,
    "last_reset": datetime.datetime.utcnow().isoformat() + "Z",
    "last_scan_duration_seconds": 0.0,
    "cumulative_scan_time_seconds": 0.0
}

def load_stats():
    try:
        with _persistence_lock:
            if os.path.exists(_STATS_FILE):
                with open(_STATS_FILE, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            else:
                with open(_STATS_FILE, "w", encoding="utf-8") as fh:
                    json.dump(_default_stats, fh, ensure_ascii=False, indent=2)
                return dict(_default_stats)
    except Exception as e:
        hydra_logger.logger.warning("Failed to load stats, using defaults: {}".format(e))
        return dict(_default_stats)

def save_stats(stats):
    try:
        with _persistence_lock:
            with open(_STATS_FILE, "w", encoding="utf-8") as fh:
                json.dump(stats, fh, ensure_ascii=False, indent=2, default=str)
    except Exception as e:
        hydra_logger.logger.warning("Failed to save stats: {}".format(e))

STATS = load_stats()

# --- Scan control flags (pause/stop) ---
SCAN_STOP = threading.Event()    # set() to request immediate stop/cancel
SCAN_PAUSED = threading.Event()  # set() to pause; clear() to resume

def audit_log(msg):
    if not AUDIT_LOG_ENABLED:
        return
    try:
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write("[{}] {}\n".format(ts, msg))
    except Exception:
        hydra_logger.logger.debug("Failed to write audit log.", exc_info=True)

# --- Persistence helpers (scan history, known malware) ---
def load_scan_history():
    with _persistence_lock:
        try:
            if os.path.exists(_SCAN_HISTORY_FILE):
                with open(_SCAN_HISTORY_FILE, "r", encoding="utf-8") as fh:
                    return json.load(fh)
        except Exception as e:
            hydra_logger.logger.warning("Failed to load scan history: {}".format(e))
    return []

def save_scan_history(history_list):
    with _persistence_lock:
        try:
            with open(_SCAN_HISTORY_FILE, "w", encoding="utf-8") as fh:
                json.dump(history_list, fh, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            hydra_logger.logger.error("Failed to save scan history: {}".format(e))

def load_known_malware():
    with _persistence_lock:
        try:
            if os.path.exists(_KNOWN_MALWARE_FILE):
                with open(_KNOWN_MALWARE_FILE, "r", encoding="utf-8") as fh:
                    return json.load(fh)
        except Exception as e:
            hydra_logger.logger.warning("Failed to load known malware store: {}".format(e))
    return {}

def save_known_malware(km):
    with _persistence_lock:
        try:
            with open(_KNOWN_MALWARE_FILE, "w", encoding="utf-8") as fh:
                json.dump(km, fh, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            hydra_logger.logger.error("Failed to save known malware store: {}".format(e))

# --- User-defined whitelist persistence ---
_WHITELIST_FILE = os.path.join(base_dir, "whitelist.json")

def load_whitelist():
    with _persistence_lock:
        try:
            if os.path.exists(_WHITELIST_FILE):
                with open(_WHITELIST_FILE, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if isinstance(data, dict):
                        return {
                            'paths': list(data.get('paths', [])),
                            'md5s': list(data.get('md5s', []))
                        }
        except Exception as e:
            hydra_logger.logger.warning("Failed to load whitelist: {}".format(e))
    return {'paths': [], 'md5s': []}

def save_whitelist(w):
    with _persistence_lock:
        try:
            payload = {'paths': list(w.get('paths', [])), 'md5s': list(w.get('md5s', []))}
            with open(_WHITELIST_FILE, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            hydra_logger.logger.error("Failed to save whitelist: {}".format(e))

def is_whitelisted(path, md5=None):
    try:
        wl = load_whitelist()
        path_norm = (path or '').lower()
        for p in wl.get('paths', []):
            try:
                if p and p.lower() in path_norm:
                    return True
            except Exception:
                continue
        if md5:
            if md5 in wl.get('md5s', []):
                return True
    except Exception as e:
        hydra_logger.logger.debug("Whitelist check failed: {}".format(e), exc_info=True)
    return False

# --- Small helper to ensure JSON-friendly value types in results ---
def _sanitize_result_for_persistence(r):
    try:
        sanitized = dict(r)
        if 'suspicious_score' in sanitized:
            try:
                sanitized['suspicious_score'] = float(sanitized['suspicious_score'])
            except Exception:
                sanitized['suspicious_score'] = str(sanitized['suspicious_score'])
        if 'flagging_reasons' in sanitized and sanitized['flagging_reasons'] is not None:
            sanitized['flagging_reasons'] = [str(x) for x in sanitized['flagging_reasons']]
        if 'md5' in sanitized:
            sanitized['md5'] = sanitized.get('md5') and str(sanitized.get('md5')) or None
        return sanitized
    except Exception:
        try:
            return str(r)
        except Exception:
            return {"error": "unserializable_result"}

# --- Obfuscation Detection Patterns ---
def is_obfuscated_string(s):
    if not s or len(s) < 3:
        return False
    non_printable_count = sum(1 for c in s if c not in string.printable)
    if non_printable_count > len(s) * 0.3:
        return True
    special_chars = sum(1 for c in s if c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`')
    if special_chars > len(s) * 0.4:
        return True
    if re.search(r'[A-Za-z0-9+/]{20,}={0,2}$', s):
        return True
    if re.search(r'^[0-9A-Fa-f]{16,}$', s):
        return True
    common_words = ['kernel32', 'ntdll', 'advapi32', 'user32', 'shell32']
    reversed_s = s[::-1].lower()
    if any(word in reversed_s for word in common_words):
        return True
    if re.search(r'[a-z][A-Z][a-z][A-Z]', s):
        return True
    return False

def calculate_string_entropy(s):
    if not s:
        return 0
    char_counts = {}
    for char in s:
        char_counts[char] = char_counts.get(char, 0) + 1
    entropy = 0
    length = len(s)
    for count in char_counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

# --- Script obfuscation heuristics (new) ---
def analyze_script_obfuscation(path):
    """
    Score text/script-based obfuscation heuristics for common script files.
    Returns (score_float, reasons_list).
    """
    score = 0.0
    reasons = []
    try:
        ext = os.path.splitext(path or "")[1].lower()
        script_exts = ('.js', '.mjs', '.cjs', '.ps1', '.py', '.vbs', '.vbe', '.bat', '.cmd', '.wsf', '.jse', '.hta', '.sh')
        if ext not in script_exts:
            return 0.0, []

        # read up to 1MB to avoid huge files
        with open(path, "rb") as fh:
            raw = fh.read(1024 * 1024)
        try:
            content = raw.decode('utf-8', errors='ignore')
        except Exception:
            content = str(raw)

        # ---------- browser session data detection to avoid false positives ----------
        try:
            if CONFIG.get("enable_browser_session_data_detection", True):
                is_browser_data, browser_type, final_reason = is_legitimate_browser_session_data(content)
                if is_browser_data:
                    reasons.append("Likely database/dump file ({}): {}".format(browser_type or "unknown", final_reason or "heuristic"))
                    # return clean/low score so browser session data dumps don't trigger obfuscation heuristics
                    return 0.0, reasons
        except Exception as e:
            hydra_logger.logger.debug("Database detection failed for {}: {}".format(path, e), exc_info=True)

        # heuristic: long base64-like blobs
        b64_matches = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content)
        if b64_matches:
            add = min(len(b64_matches) * 6, 24)
            score += add
            reasons.append("{:d} long base64-like blobs found (+{:d})".format(len(b64_matches), int(add)))

        # many escaped hex sequences like \xNN (common in JS obfuscation)
        hex_escapes = len(re.findall(r'\\x[0-9A-Fa-f]{2}', content))
        if hex_escapes > 10:
            score += 8
            reasons.append("{} hex escape sequences (\\x..) (+8)".format(hex_escapes))
        elif hex_escapes > 3:
            score += 4
            reasons.append("{} hex escape sequences (\\x..) (+4)".format(hex_escapes))

        # eval/Function/exec usage (suspicious pattern)
        eval_tokens = 0
        for tok in ('eval(', 'Function(', 'new Function', 'setTimeout(', 'setInterval(', 'exec(', 'Invoke-Expression', 'IEX '):
            eval_tokens += content.count(tok)
        if eval_tokens > 0:
            add = min(eval_tokens * 3, 12)
            score += add
            reasons.append("{} suspicious evaluation/exec tokens (+{})".format(eval_tokens, int(add)))

        # long lines (single-line obfuscated payloads)
        lines = content.splitlines()
        long_lines = sum(1 for l in lines if len(l) > 300)
        if long_lines:
            add = min(long_lines * 3, 12)
            score += add
            reasons.append("{} very long lines detected (+{})".format(long_lines, int(add)))

        # --- NEW: strong detection for a single extreme line ---
        # If there's one very large line (common in packed/one-line obfuscation),
        # give a substantial score bump so a single extreme line can trigger detection.
        try:
            max_len = max((len(l) for l in lines), default=0)
            if max_len > 5000:
                # monster line (e.g. >5KB) -> heavy penalty
                score += 20
                reasons.append("Contains one EXTREMELY long line of {} characters (+20)".format(max_len))
            elif max_len > 2000:
                # large single line -> strong penalty
                score += 12
                reasons.append("Contains one very long line of {} characters (+12)".format(max_len))
            elif max_len > 1000:
                # moderate single-line penalty
                score += 6
                reasons.append("Contains a long line of {} characters (+6)".format(max_len))
        except Exception:
            # non-fatal if max calculation fails
            pass

        # concatenation tokens (crude proxy)
        concat_ops = content.count('+') + content.count('.')
        if concat_ops > 500:
            score += 8
            reasons.append("Very high concatenation token count (+8)")

        # text entropy on sample
        sample = content[:2000]
        ent = calculate_string_entropy(sample)
        if ent > 4.2:
            score += 6
            reasons.append("High text entropy in sample ({:.2f}) (+6)".format(ent))

        non_alnum_ratio = sum(1 for c in sample if not c.isalnum() and not c.isspace()) / (len(sample) or 1)
        if non_alnum_ratio > 0.25:
            score += 4
            reasons.append("High non-alphanumeric ratio in sample (+4)")

        # cap
        if score > 60:
            score = 60.0

    except Exception as e:
        reasons.append("Script analysis failed: {}".format(e))
        hydra_logger.logger.debug("Script obfuscation analysis failed for {}: {}".format(path, e), exc_info=True)
    return float(score), reasons

# --- Analysis modules (unchanged semantics, kept as functions) ---
def detect_packing_heuristics(pe_features):
    score = 0
    reasons = []
    disasm = pe_features.get('section_disassembly', {}).get('overall_analysis', {})
    if disasm.get('is_likely_packed'):
        score += 10
        reasons.append("Assembly analysis indicates packing (+10)")
    add_count = disasm.get('add_count', 0)
    mov_count = disasm.get('mov_count', 0)
    if mov_count > 0 and (add_count / mov_count) > 2:
        score += 8
        reasons.append("Suspicious ADD/MOV instruction ratio (+8)")
    sections = pe_features.get('section_characteristics', {})
    high_entropy_sections = 0
    for section_name, data in sections.items():
        entropy = data.get('entropy', 0)
        if entropy > 7.0:
            high_entropy_sections += 1
    if high_entropy_sections > 1:
        score += 8
        reasons.append("Multiple high-entropy sections detected (+8)")
    elif high_entropy_sections == 1:
        score += 4
        reasons.append("High-entropy section detected (+4)")
    pe_sections = pe_features.get('sections', [])
    if pe_sections:
        total_virtual = sum(s.get('virtual_size', 0) for s in pe_sections)
        total_raw = sum(s.get('size_of_raw_data', 0) for s in pe_sections)
        if total_raw > 0 and (total_virtual / total_raw) > 3:
            score += 6
            reasons.append("Suspicious virtual/raw size ratio (+6)")
    return score, reasons

def analyze_section_obfuscation(pe_features):
    score = 0
    reasons = []
    sections = pe_features.get('sections', [])
    section_chars = pe_features.get('section_characteristics', {})
    for section in sections:
        section_name = section.get('name', '')
        if is_obfuscated_string(section_name):
            score += 8
            reasons.append("Obfuscated section name '{}' (+8)".format(section_name))
        if section_name and not section_name.startswith(('.text', '.data', '.rdata', '.rsrc', '.reloc', '.idata')):
            name_entropy = calculate_string_entropy(section_name)
            if name_entropy > 3.5:
                score += 5
                reasons.append("High-entropy section name '{}' (+5)".format(section_name))
        characteristics = section.get('characteristics', 0)
        if characteristics & 0x20000000 and characteristics & 0x80000000:  # Execute + Write
            score += 6
            reasons.append("Section '{}' has execute+write characteristics (+6)".format(section_name))
    for section_name, data in section_chars.items():
        flags = data.get('flags', {})
        if flags.get('MEM_EXECUTE') and flags.get('MEM_WRITE'):
            score += 7
            reasons.append("Section '{}' is both executable and writable (+7)".format(section_name))
        size_ratio = data.get('size_ratio', 0)
        if size_ratio > 0.8:
            score += 4
            reasons.append("Section '{}' takes up {}% of image (+4)".format(section_name, int(size_ratio * 100)))
    return score, reasons

def analyze_import_obfuscation(pe_features):
    score = 0
    reasons = []
    imports = pe_features.get('imports', [])
    obfuscated_imports = 0
    for imp_name in imports:
        if imp_name and is_obfuscated_string(imp_name):
            obfuscated_imports += 1
    if obfuscated_imports > 0:
        score += min(obfuscated_imports * 3, 15)
        reasons.append("{} obfuscated import names (+{})".format(obfuscated_imports, min(obfuscated_imports * 3, 15)))
    if len(imports) == 0:
        score += 8
        reasons.append("No imports detected - possible import obfuscation (+8)")
    elif len(imports) < 5:
        score += 4
        reasons.append("Very few imports - possible selective import loading (+4)")
    delay_imports = pe_features.get('delay_imports', [])
    if len(delay_imports) > len(imports):
        score += 6
        reasons.append("More delay imports than regular imports (+6)")
    return score, reasons

def analyze_header_anomalies(pe_features):
    score = 0
    reasons = []
    checksum = pe_features.get('CheckSum', 0)
    if checksum == 0:
        score += 3
        reasons.append("PE checksum is zero (+3)")
    loader_flags = pe_features.get('LoaderFlags', 0)
    if loader_flags != 0:
        score += 5
        reasons.append("Non-zero LoaderFlags: 0x{:x} (+5)".format(loader_flags))
    subsystem = pe_features.get('Subsystem', 0)
    if subsystem not in [1, 2, 3, 5, 6, 7, 8, 9, 10, 14, 16]:
        score += 6
        reasons.append("Unknown subsystem value: {} (+6)".format(subsystem))
    entry_point = pe_features.get('AddressOfEntryPoint', 0)
    sections = pe_features.get('sections', [])
    entry_in_non_code_section = True
    for section in sections:
        va_start = section.get('virtual_address', 0)
        va_size = section.get('virtual_size', 0)
        if va_start <= entry_point < va_start + va_size:
            section_name = section.get('name', '')
            if section_name.startswith('.text') or 'CODE' in section_name.upper():
                entry_in_non_code_section = False
            break
    if entry_in_non_code_section and entry_point != 0:
        score += 8
        reasons.append("Entry point not in code section (+8)")
    return score, reasons

def analyze_resource_anomalies(pe_features):
    score = 0
    reasons = []
    resources = pe_features.get('resources') if isinstance(pe_features, dict) else None
    if not resources:
        resources = []
    elif not isinstance(resources, list):
        try:
            resources = list(resources)
        except Exception:
            resources = []
    large_resources = 0
    for resource in resources:
        res_size = 0
        try:
            if isinstance(resource, dict):
                res_size = int(resource.get('size') or 0)
            else:
                res_size = int(resource)
        except Exception:
            res_size = 0
        if res_size > 1024 * 1024:
            large_resources += 1
    if large_resources > 0:
        score += large_resources * 3
        reasons.append("{} large resources (>1MB each) (+{})".format(large_resources, large_resources * 3))
    try:
        if len(resources) > 50:
            score += 5
            reasons.append("Excessive number of resources: {} (+5)".format(len(resources)))
    except Exception:
        pass
    return score, reasons

def analyze_tls_anomalies(pe_features):
    score = 0
    reasons = []
    tls_callbacks = pe_features.get('tls_callbacks', {})
    callbacks = tls_callbacks.get('callbacks', [])
    if callbacks:
        score += 8
        reasons.append("TLS callbacks detected - possible anti-analysis (+8)")
        if len(callbacks) > 3:
            score += 4
            reasons.append("Multiple TLS callbacks: {} (+4)".format(len(callbacks)))
    return score, reasons

def analyze_rich_header_anomalies(pe_features):
    score = 0
    reasons = []
    rich_header = pe_features.get('rich_header', {})
    if rich_header and not rich_header.get('comp_id_info'):
        score += 4
        reasons.append("Rich header present but no compiler info (+4)")
    comp_info = rich_header.get('comp_id_info', [])
    for comp in comp_info:
        comp_id = comp.get('comp_id', 0)
        if comp_id > 300 or comp_id == 0:
            score += 3
            reasons.append("Suspicious compiler ID: {} (+3)".format(comp_id))
            break
    return score, reasons

def analyze_overlay_anomalies(pe_features):
    score = 0
    reasons = []
    overlay = pe_features.get('overlay', {})
    if overlay.get('exists'):
        overlay_size = overlay.get('size', 0)
        overlay_entropy = overlay.get('entropy', 0)
        score += 5
        reasons.append("Overlay data detected (+5)")
        if overlay_entropy > 7.5:
            score += 6
            reasons.append("High-entropy overlay data (+6)")
        if overlay_size > 100 * 1024:
            score += 4
            reasons.append("Large overlay: {} bytes (+4)".format(overlay_size))
    return score, reasons

# --- Utility Functions (unchanged) ---
def calculate_entropy(path):
    freq = [0] * 256
    total = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                for b in chunk:
                    if isinstance(b, int):
                        freq[b] += 1
                    else:
                        freq[ord(b)] += 1
        entropy = 0.0
        if total > 0:
            for f in freq:
                if f > 0:
                    p = float(f) / total
                    entropy -= p * math.log2(p)
        return entropy
    except Exception as e:
        hydra_logger.logger.debug("Entropy calc failed for {}: {}".format(path, e), exc_info=True)
        return 0.0

def is_running_pe(path):
    try:
        if not psutil:
            return False
        for proc in psutil.process_iter(['exe', 'name']):
            try:
                exe = proc.info.get('exe')
                if exe and os.path.normcase(exe) == os.path.normcase(path):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return False

def is_in_suspicious_location_pe(path):
    path_norm = os.path.normcase(path)
    for d in SUSPICIOUS_DIRS + STARTUP_DIRS:
        if d and os.path.normcase(d) in path_norm:
            return True
    return False

# --- Safe-run helper to isolate analyzer function exceptions ---
def _safe_run(name, func, *args, **kwargs):
    try:
        result = func(*args, **kwargs)
        if isinstance(result, tuple) and len(result) == 2:
            score, reasons = result
            try:
                score = float(score)
            except Exception:
                try:
                    score = int(score)
                except Exception:
                    score = 0
            if reasons is None:
                reasons = []
            else:
                try:
                    reasons = [str(x) for x in reasons]
                except Exception:
                    reasons = [str(reasons)]
            return score, reasons
        else:
            hydra_logger.logger.warning("Analyzer '%s' returned unexpected type: %s", name, type(result))
            return 0, []
    except Exception as e:
        tb = traceback.format_exc()
        hydra_logger.logger.error("Analysis function '%s' raised: %s\n%s", name, e, tb)
        return 0, ["{} analysis failed: {}".format(name, str(e))]

# --- New helper: probable-installer heuristic (scientific, auditable) ---
def is_probable_installer(path, pe_features):
    """
    Heuristic check for installer-like files.
    Returns True for common installer types (.msi, .msix, .msp),
    filenames containing installer tokens, or pe metadata/imports that point to installer frameworks.
    """
    try:
        # extension checks
        ext = os.path.splitext(path or "")[1].lower()
        if ext in ('.msi', '.msix', '.msm', '.msp'):
            return True

        # filename clues
        name = os.path.basename(path or "").lower()
        if any(token in name for token in ('setup', 'install', 'installer', 'uninstall', 'update', 'patch', 'setup32', 'setup64')):
            return True

        # metadata clues
        try:
            desc = ''
            prod = ''
            if isinstance(pe_features, dict):
                desc = (pe_features.get('file_description') or pe_features.get('FileDescription') or '') or ''
                prod = (pe_features.get('product_name') or pe_features.get('ProductName') or '') or ''
                desc = desc.lower()
                prod = prod.lower()
                if any(k in desc for k in ('installer', 'inno', 'nsis', 'installshield')):
                    return True
                if any(k in prod for k in ('installer', 'inno', 'nsis', 'installshield')):
                    return True
        except Exception:
            pass

        # imports / API clues
        try:
            imports = pe_features.get('imports') if isinstance(pe_features, dict) else []
            for imp in (imports or []):
                if not imp:
                    continue
                ik = imp.lower()
                if any(token in ik for token in ('msi', 'setupapi', 'cabinet', 'cabinetlib', 'installshield', 'instmsi', 'nsis')):
                    return True
        except Exception:
            pass

    except Exception:
        return False

    return False

# --- Core Analysis Logic (with RAPPS whitelist + installer adjustment) ---
def _append_history_and_known(result):
    try:
        history = load_scan_history()
        sanitized = _sanitize_result_for_persistence(result)
        history.append(sanitized)
        if len(history) > 5000:
            history = history[-5000:]
        save_scan_history(history)
        if result.get('suspicious'):
            md5 = compute_md5(result.get('path')) or result.get('md5')
            known = load_known_malware()
            if md5:
                known_entry = known.get(md5, {})
                known_entry.update({
                    'path': result.get('path'),
                    'first_seen': known_entry.get('first_seen', datetime.datetime.utcnow().isoformat() + "Z"),
                    'last_seen': datetime.datetime.utcnow().isoformat() + "Z",
                    'detection_name': result.get('detection_name'),
                    'score': result.get('suspicious_score'),
                    'reasons': result.get('flagging_reasons'),
                    'quarantined': known_entry.get('quarantined', result.get('status') == 'Quarantined')
                })
                known[md5] = known_entry
                save_known_malware(known)
    except Exception as e:
        hydra_logger.logger.warning("Failed to append history/known store: {}".format(e), exc_info=True)

def compute_md5(file_path):
    import hashlib
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        hydra_logger.logger.error("Could not compute MD5 for {}: {}".format(file_path, e))
        return None

def analyze_single_file(path):
    """
    Analyzes a single file using hardcoded obfuscation detection.
    Adds RAPPS auto-whitelist and installer score adjustment as configured.
    Also handles script/text obfuscation detection for script extensions.

    NOTE: Scripts are evaluated *only* against SCRIPT_SUSPICIOUS_THRESHOLD (default ~15)
    and will NOT be compared to the PE SUSPICIOUS_THRESHOLD (default 43). This prevents
    scripts from being flagged by the PE threshold.
    """
    global STATS, SCRIPT_SUSPICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD
    analysis_result = {
        'path': path,
        'suspicious': False,
        'detection_name': "Clean",
        'suspicious_score': 0.0,
        'suspicious_score_display': "0%",   # human-readable score with % suffix
        'flagging_reasons': [],
        'status': 'Scanned',
        'md5': compute_md5(path)
    }

    # Count total scanned (stat)
    try:
        STATS['total_scanned'] = STATS.get('total_scanned', 0) + 1
    except Exception:
        pass

    # Check user whitelist (paths or MD5s)
    try:
        try_md5 = analysis_result.get('md5')
    except Exception:
        try_md5 = None
    if is_whitelisted(path, try_md5):
        analysis_result.update({
            'suspicious': False,
            'detection_name': 'Whitelisted',
            'status': 'Whitelisted',
            'flagging_reasons': ['User whitelist'],
            'suspicious_score_display': "0%"
        })
        try:
            _append_history_and_known(analysis_result)
        except Exception:
            hydra_logger.logger.debug("Failed to persist whitelisted result.", exc_info=True)
        return analysis_result

    # Defensive: ensure file still exists before processing
    try:
        if not os.path.exists(path):
            analysis_result['detection_name'] = "File missing"
            analysis_result['status'] = 'Skipped'
            _append_history_and_known(analysis_result)
            return analysis_result
    except Exception:
        pass

    # RAPPS auto-whitelist (configurable)
    try:
        if ENABLE_RAPPS_WHITELIST and is_rapps_whitelisted(path):
            analysis_result.update({
                'suspicious': False,
                'detection_name': 'Whitelisted - RAPPS Downloads',
                'status': 'Whitelisted',
                'flagging_reasons': ['RAPPS Downloads trusted folder'],
                'suspicious_score_display': "0%"
            })
            _append_history_and_known(analysis_result)
            # update stats
            try:
                STATS['rapps_whitelisted'] = STATS.get('rapps_whitelisted', 0) + 1
                save_stats(STATS)
            except Exception:
                pass
            audit_log("RAPPS auto-whitelisted: {}".format(path))
            return analysis_result
    except Exception as e:
        hydra_logger.logger.debug("RAPPS auto-whitelist check failed for {}: {}".format(path, e), exc_info=True)

    # --- SCRIPT-SPECIFIC HANDLING: run BEFORE any PE feature extraction ---
    # This ensures scripts are only checked against SCRIPT_SUSPICIOUS_THRESHOLD and
    # cannot be accidentally flagged by the PE threshold (SUSPICIOUS_THRESHOLD).
    try:
        ext = os.path.splitext(path or "")[1].lower()
        script_exts = ('.js', '.mjs', '.cjs', '.ps1', '.py', '.vbs', '.vbe', '.bat', '.cmd', '.wsf', '.jse', '.hta', '.sh')
        if ext in script_exts:
            sc_score, sc_reasons = analyze_script_obfuscation(path)
            analysis_result['suspicious_score'] = sc_score
            analysis_result['flagging_reasons'] = sc_reasons
            analysis_result['suspicious_score_display'] = "{}%".format(int(sc_score))
            # Use the dedicated script threshold — do NOT compare to SUSPICIOUS_THRESHOLD
            if sc_score >= float(SCRIPT_SUSPICIOUS_THRESHOLD):
                analysis_result.update({
                    'suspicious': True,
                    'detection_name': "HEUR:Script.Obfuscated_conf_{}%".format(int(sc_score)),
                    'status': 'Detection',
                    'confidence': int(sc_score)
                })
                try:
                    STATS['total_detections'] = STATS.get('total_detections', 0) + 1
                except Exception:
                    pass
                hydra_logger.logger.info("[Script-Suspicious] File: {} | Score: {} | Reasons: {}".format(
                    path, sc_score, "; ".join(sc_reasons)
                ))
            else:
                analysis_result.update({
                    'suspicious': False,
                    'detection_name': "HEUR:Script.Clean(Score:{}%)".format(int(sc_score)),
                    'status': 'Scanned',
                    'confidence': int(sc_score)
                })
            _append_history_and_known(analysis_result)
            return analysis_result
    except Exception as e:
        hydra_logger.logger.debug("Script analysis early-exit failed for {}: {}".format(path, e), exc_info=True)
        # fall through to normal handling (non-script case) if an unexpected error occurs

    # --- PE / binary handling continues here ---
    try:
        pe_features = None
        try:
            pe_features = get_cached_pe_features(path)
        except Exception as e:
            hydra_logger.logger.error("get_cached_pe_features raised for %s: %s", path, e, exc_info=True)
            pe_features = None

        if pe_features is None:
            analysis_result['detection_name'] = "Not a PE file or unreadable"
            analysis_result['status'] = 'Skipped'
            _append_history_and_known(analysis_result)
            return analysis_result

        if not hasattr(pe_features, 'get'):
            hydra_logger.logger.warning("get_cached_pe_features returned unexpected type (%s) for %s", type(pe_features), path)
            try:
                pe_features = dict(pe_features)
            except Exception:
                analysis_result['detection_name'] = "PE features malformed"
                analysis_result['status'] = 'Skipped'
                _append_history_and_known(analysis_result)
                return analysis_result

        total_score = 0.0
        all_reasons = []

        # Run each analyzer using safe wrapper
        score, reasons = _safe_run('detect_packing_heuristics', detect_packing_heuristics, pe_features)
        total_score += score
        all_reasons.extend(reasons)

        score, reasons = _safe_run('analyze_section_obfuscation', analyze_section_obfuscation, pe_features)
        total_score += score
        all_reasons.extend(reasons)

        score, reasons = _safe_run('analyze_import_obfuscation', analyze_import_obfuscation, pe_features)
        total_score += score
        all_reasons.extend(reasons)

        score, reasons = _safe_run('analyze_header_anomalies', analyze_header_anomalies, pe_features)
        total_score += score
        all_reasons.extend(reasons)

        score, reasons = _safe_run('analyze_resource_anomalies', analyze_resource_anomalies, pe_features)
        total_score += score
        all_reasons.extend(reasons)

        score, reasons = _safe_run('analyze_tls_anomalies', analyze_tls_anomalies, pe_features)
        total_score += score
        all_reasons.extend(reasons)

        score, reasons = _safe_run('analyze_rich_header_anomalies', analyze_rich_header_anomalies, pe_features)
        total_score += score
        all_reasons.extend(reasons)

        score, reasons = _safe_run('analyze_overlay_anomalies', analyze_overlay_anomalies, pe_features)
        total_score += score
        all_reasons.extend(reasons)

        # Additional heuristics
        try:
            if is_running_pe(path):
                total_score += 5
                all_reasons.append("Process is actively running (+5)")
        except Exception as e:
            hydra_logger.logger.debug("is_running_pe failed for %s: %s", path, e, exc_info=True)

        try:
            if is_in_suspicious_location_pe(path):
                total_score += 5
                all_reasons.append("Located in suspicious directory (+5)")
        except Exception as e:
            hydra_logger.logger.debug("is_in_suspicious_location_pe failed for %s: %s", path, e, exc_info=True)

        try:
            file_entropy = calculate_entropy(path)
            if file_entropy > 7.8:
                total_score += 8
                all_reasons.append("Very high file entropy: {:.2f} (+8)".format(file_entropy))
            elif file_entropy > 7.5:
                total_score += 4
                all_reasons.append("High file entropy: {:.2f} (+4)".format(file_entropy))
        except Exception as e:
            hydra_logger.logger.debug("calculate_entropy failed for %s: %s", path, e, exc_info=True)

        try:
            stats = os.stat(path)
            age_days = (time.time() - stats.st_ctime) / (24 * 3600)
            if age_days < 1:
                total_score += 3
                all_reasons.append("Recent file ({:.1f} days) (+3)".format(age_days))
        except Exception as e:
            hydra_logger.logger.debug("os.stat failed for %s: %s", path, e, exc_info=True)

        try:
            if not (pe_features.get('certificates', {}) or {}).get('fixed_file_info'):
                total_score += 2
                all_reasons.append("No version information (+2)")
        except Exception as e:
            hydra_logger.logger.debug("certificates check failed for %s: %s", path, e, exc_info=True)

        # === Installer heuristic adjustment (configurable) ===
        try:
            if ENABLE_INSTALLER_ADJUSTMENT and is_probable_installer(path, pe_features):
                prev_score = float(total_score)
                total_score = max(0.0, float(total_score) - INSTALLER_SCORE_DEDUCTION)
                all_reasons.append("Installer heuristic adjustment (-{})".format(int(INSTALLER_SCORE_DEDUCTION)))
                try:
                    STATS['installer_adjustments_applied'] = STATS.get('installer_adjustments_applied', 0) + 1
                except Exception:
                    pass
                audit_log("Installer adjustment: file={} prev_score={} new_score={}".format(path, prev_score, total_score))
        except Exception as e:
            hydra_logger.logger.debug("Installer heuristic adjustment failed for {}: {}".format(path, e), exc_info=True)

        # finalize
        analysis_result['suspicious_score'] = total_score
        analysis_result['suspicious_score_display'] = "{}%".format(int(total_score))
        analysis_result['flagging_reasons'] = all_reasons

        if total_score >= float(SUSPICIOUS_THRESHOLD):
            confidence = int(total_score)
            analysis_result.update({
                'suspicious': True,
                'detection_name': "{}_confidence_{}%".format(DETECTION_NAME, confidence),
                'status': 'Detection',
                'confidence': confidence
            })
            hydra_logger.logger.info(
                "[Suspicious] File: {} | Score: {} | Confidence: {} | Reasons: {}".format(
                    path, total_score, confidence, "; ".join(all_reasons)
                )
            )
            try:
                STATS['total_detections'] = STATS.get('total_detections', 0) + 1
            except Exception:
                pass
        else:
            confidence = int(total_score)
            analysis_result['detection_name'] = "Clean (Score: {}%)".format(int(total_score))
            analysis_result['confidence'] = confidence

        # If adjustment was applied and this file would have been detected before adjustment,
        # we consider it as "detection prevented by adjustment" for stats and audit.
        try:
            if ENABLE_INSTALLER_ADJUSTMENT and any('Installer heuristic adjustment' in r for r in all_reasons):
                hypothetical_score = float(analysis_result['suspicious_score']) + float(INSTALLER_SCORE_DEDUCTION)
                if hypothetical_score >= float(SUSPICIOUS_THRESHOLD) and analysis_result.get('suspicious') == False:
                    STATS['detections_prevented_by_adjustment'] = STATS.get('detections_prevented_by_adjustment', 0) + 1
                    audit_log("Detection prevented by adjustment: file={} hypothetical_score={} threshold={}".format(
                        path, hypothetical_score, SUSPICIOUS_THRESHOLD))
        except Exception:
            pass

    except Exception as e:
        hydra_logger.logger.error("Failed to analyze {}: {}".format(path, e), exc_info=True)
        analysis_result.update({
            'detection_name': "Analysis-Error",
            'flagging_reasons': [str(e)],
            'status': 'Error',
            'suspicious_score_display': "{}%".format(int(analysis_result.get('suspicious_score', 0)))
        })

    # persist result & known-malware entry if applicable
    try:
        _append_history_and_known(analysis_result)
    except Exception:
        hydra_logger.logger.debug("Failed to persist analysis result for {}".format(path), exc_info=True)

    # try to save stats periodically
    try:
        save_stats(STATS)
    except Exception:
        pass

    return analysis_result

def scan_directory_parallel(directory, app_instance, max_workers=None):
    file_paths = []
    app_instance.update_status("Collecting files...")
    for root, _, files in os.walk(directory):
        for f in files:
            file_paths.append(os.path.join(root, f))
    total = len(file_paths)
    if total == 0:
        # report zero-duration
        app_instance.scan_finished(0, 0, 0.0)
        return
    workers = max_workers or min(100, max(4, (os.cpu_count() or 2) * 4))
    processed_count = 0
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(analyze_single_file, p): p for p in file_paths}
        try:
            for fut in as_completed(futures):
                # If user requested a stop, attempt to cancel remaining tasks and break.
                if SCAN_STOP.is_set():
                    try:
                        for f in futures:
                            try:
                                f.cancel()
                            except Exception:
                                pass
                    except Exception:
                        pass
                    break

                # If paused, wait here (but remain responsive to Stop)
                while SCAN_PAUSED.is_set() and not SCAN_STOP.is_set():
                    try:
                        app_instance.update_status("Scan paused... ({}/{})".format(processed_count, total))
                    except Exception:
                        pass
                    time.sleep(0.25)

                p = futures[fut]
                processed_count += 1
                app_instance.update_progress(processed_count, total)
                try:
                    res = fut.result()
                    if res:
                        app_instance.add_result(res)
                except Exception as e:
                    hydra_logger.logger.exception("Worker failed for {}: {}".format(p, e))
        except Exception as e:
            hydra_logger.logger.exception("scan_directory_parallel main loop failure: {}".format(e))

    elapsed = time.time() - start_time

    # persist timing stats
    try:
        STATS['last_scan_duration_seconds'] = float(elapsed)
        STATS['cumulative_scan_time_seconds'] = STATS.get('cumulative_scan_time_seconds', 0.0) + float(elapsed)
        save_stats(STATS)
    except Exception:
        hydra_logger.logger.debug("Failed to persist scan timing stats.", exc_info=True)

    # Determine number of detections in the current view
    detections = len([r for r in app_instance.scan_results if r.get('suspicious')])

    # If we stopped early, use processed_count; else total
    final_total = processed_count if SCAN_STOP.is_set() else total
    app_instance.scan_finished(final_total, detections, elapsed)

# --- GUI Application (with toggles for rappps & installer adjustment) ---
class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HydraScanner - Hardcoded Obfuscation Detection (RAPPS + Installer Adjustment)")
        self.root.geometry("1000x700")
        self.root.minsize(900, 500)
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except Exception:
            pass
        # Styling (keeps previous theme choices)
        self.style.configure("TFrame", background="#2E2E2E")
        self.style.configure("TButton", background="#4A4A4A", foreground="white", relief="flat", padding=5)
        try:
            self.style.map("TButton", background=[('active', '#5A5A5A')])
        except Exception:
            pass
        self.style.configure("TLabel", background="#2E2E2E", foreground="white")
        self.style.configure("Treeview", rowheight=25, fieldbackground="#1C1C1C", background="#1C1C1C", foreground="#D3D3D3", borderwidth=0)
        self.style.configure("Treeview.Heading", background="#4A4A4A", foreground="white", relief="flat", font=('Arial', 10, 'bold'))
        try:
            self.style.map("Treeview.Heading", background=[('active', '#5A5A5A')])
        except Exception:
            pass
        self.style.configure("Vertical.TScrollbar", background='#4A4A4A', troughcolor='#2E2E2E', arrowcolor='white')
        self.root.configure(bg='#2E2E2E')

        # runtime options (bound to config)
        self.enable_rapps_var = tk.BooleanVar(value=ENABLE_RAPPS_WHITELIST)
        self.enable_inst_adj_var = tk.BooleanVar(value=ENABLE_INSTALLER_ADJUSTMENT)

        self.scan_results = []
        self._create_widgets()
        # load persistent history into view
        try:
            persisted = load_scan_history()
            for r in persisted[-1000:]:
                r['tree_id'] = None
                self.scan_results.append(r)
            self.apply_filter()
        except Exception:
            hydra_logger.logger.debug("Failed to load persisted scan history.", exc_info=True)

    def _create_widgets(self):
        # --- Top frame: controls stacked vertically ---
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill=tk.X)

        # --- Scan buttons ---
        scan_frame = ttk.Frame(top_frame)
        scan_frame.pack(fill=tk.X, pady=2)
        self.scan_button = ttk.Button(scan_frame, text="Select Directory & Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=2)
        self.pause_button = ttk.Button(scan_frame, text="Pause", command=self.pause_scan, state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT, padx=2)
        self.resume_button = ttk.Button(scan_frame, text="Resume", command=self.resume_scan, state=tk.DISABLED)
        self.resume_button.pack(side=tk.LEFT, padx=2)
        self.stop_button = ttk.Button(scan_frame, text="Stop", command=self.cancel_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=2)

        # --- Options & filters ---
        options_frame = ttk.Frame(top_frame)
        options_frame.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(
            options_frame, text="Enable RAPPS Whitelist",
            variable=self.enable_rapps_var, command=self.toggle_rapps_whitelist
        ).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(
            options_frame,
            text="Enable Installer Adjust (-{})".format(int(INSTALLER_SCORE_DEDUCTION)),
            variable=self.enable_inst_adj_var,
            command=self.toggle_installer_adjustment
        ).pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="Detections Only")
        ttk.Radiobutton(options_frame, text="All", variable=self.filter_var,
                        value="All", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(options_frame, text="Detections Only", variable=self.filter_var,
                        value="Detections Only", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(options_frame, text="Clean Only", variable=self.filter_var,
                        value="Clean Only", command=self.apply_filter).pack(side=tk.LEFT, padx=2)

        # --- Search + Whitelist ---
        search_frame = ttk.Frame(top_frame)
        search_frame.pack(fill=tk.X, pady=2)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=2)
        search_entry.bind('<Return>', lambda e: self.apply_filter())
        ttk.Button(search_frame, text="Search", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Button(search_frame, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=2)
        ttk.Button(search_frame, text="Manage Whitelist", command=self.manage_whitelist).pack(side=tk.LEFT, padx=2)

        # --- Treeview frame ---
        tree_frame = ttk.Frame(self.root, padding=(10, 5, 10, 10))
        tree_frame.pack(expand=True, fill='both')
        columns = ("#", "file_path", "detection", "score", "status")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        for col, w in zip(columns, [60, 450, 200, 120, 100]):
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(
                col,
                width=w,
                stretch=False if col in ("#", "score", "status") else True,
                anchor='center' if col in ("score", "status") else 'w'
            )
        self.tree.pack(side=tk.LEFT, expand=True, fill='both')
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill='y')

        # >>> NEW: color tags for scan results <<<
        # These tags control row background/foreground in real time
        self.tree.tag_configure('MALICIOUS', background='#4A0000', foreground='white')   # red
        self.tree.tag_configure('CLEAN',     background='#003300', foreground='white')   # green
        self.tree.tag_configure('ERROR',     background='#333333', foreground='white')   # gray
        self.tree.tag_configure('QUARANTINED', background='#660066', foreground='white') # purple

        # Bind double-click *after* the tree is defined
        self.tree.bind('<Double-1>', lambda e: self.show_details())

        # --- Context menu (right-click) ---
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Show Details", command=self.show_details)
        self.context_menu.add_command(label="Quarantine", command=self.quarantine_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Path", command=self._context_copy_path)
        self.context_menu.add_command(label="Add path to whitelist", command=self._context_add_whitelist)

        # Bind right-click on the tree to show the context menu
        self.tree.bind("<Button-3>", self.show_context_menu)

        # --- Bottom frame: status + progress bar ---
        bottom_frame = ttk.Frame(self.root, padding=10)
        bottom_frame.pack(fill=tk.X)
        self.status_label = ttk.Label(bottom_frame, text="Ready", anchor='w')
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_bar = ttk.Progressbar(bottom_frame, orient='horizontal', mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True)

        # stats label placed on the right
        self.stats_label = ttk.Label(bottom_frame, text=self._stats_text(), anchor='e')
        self.stats_label.pack(side=tk.RIGHT)

    def _stats_text(self):
        try:
            s = STATS
            last_dur = s.get('last_scan_duration_seconds', 0.0)
            try:
                last_fmt = str(datetime.timedelta(seconds=int(last_dur)))
            except Exception:
                last_fmt = "{}s".format(int(last_dur or 0))
            return "Scanned: {}  Detections: {}  RAPPS-whitelisted: {}  Installer-adjustments: {}  Prevented: {}  LastScan: {}".format(
                s.get('total_scanned', 0), s.get('total_detections', 0),
                s.get('rapps_whitelisted', 0), s.get('installer_adjustments_applied', 0),
                s.get('detections_prevented_by_adjustment', 0),
                last_fmt
            )
        except Exception:
            return "Stats unavailable"

    def _update_stats_label(self):
        try:
            self.stats_label.config(text=self._stats_text())
        except Exception:
            pass

    def refresh_stats(self):
        global STATS
        try:
            STATS = load_stats()
        except Exception:
            pass

    def toggle_rapps_whitelist(self):
        global ENABLE_RAPPS_WHITELIST, CONFIG
        ENABLE_RAPPS_WHITELIST = bool(self.enable_rapps_var.get())
        CONFIG['enable_rapps_whitelist'] = ENABLE_RAPPS_WHITELIST
        try:
            with open(_CONFIG_FILE, "w", encoding="utf-8") as fh:
                json.dump(CONFIG, fh, ensure_ascii=False, indent=2)
        except Exception:
            hydra_logger.logger.debug("Failed to write config", exc_info=True)

    def toggle_installer_adjustment(self):
        global ENABLE_INSTALLER_ADJUSTMENT, CONFIG
        ENABLE_INSTALLER_ADJUSTMENT = bool(self.enable_inst_adj_var.get())
        CONFIG['enable_installer_adjustment'] = ENABLE_INSTALLER_ADJUSTMENT
        try:
            with open(_CONFIG_FILE, "w", encoding="utf-8") as fh:
                json.dump(CONFIG, fh, ensure_ascii=False, indent=2)
        except Exception:
            hydra_logger.logger.debug("Failed to write config", exc_info=True)

    def start_scan(self):
        directory = filedialog.askdirectory()
        if not directory:
            return

        # Reset global control flags for a fresh scan
        SCAN_STOP.clear()
        SCAN_PAUSED.clear()

        # enable pause & stop controls
        try:
            self.pause_button.config(state=tk.NORMAL)
            self.resume_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        except Exception:
            pass

        self.scan_button.config(state=tk.DISABLED)
        self.tree.delete(*self.tree.get_children())
        self.scan_results.clear()
        self.status_label.config(text="Starting hardcoded scan in: {}".format(directory))
        scan_thread = threading.Thread(target=scan_directory_parallel, args=(directory, self))
        scan_thread.daemon = True
        scan_thread.start()

    def pause_scan(self):
        """
        Pause scanning. Worker loop checks SCAN_PAUSED and will block between results.
        """
        try:
            SCAN_PAUSED.set()
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.NORMAL)
            self.update_status("Scan paused by user.")
        except Exception:
            hydra_logger.logger.debug("Failed to pause scan.", exc_info=True)

    def resume_scan(self):
        """
        Resume scanning after pause.
        """
        try:
            SCAN_PAUSED.clear()
            self.pause_button.config(state=tk.NORMAL)
            self.resume_button.config(state=tk.DISABLED)
            self.update_status("Resuming scan...")
        except Exception:
            hydra_logger.logger.debug("Failed to resume scan.", exc_info=True)

    def cancel_scan(self):
        """
        Cancel/stop the running scan. This signals worker loop to stop and attempts to cancel queued tasks.
        """
        try:
            SCAN_STOP.set()
            SCAN_PAUSED.clear()
            # disable control buttons while stopping
            self.pause_button.config(state=tk.DISABLED)
            self.resume_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.DISABLED)
            self.update_status("Stopping scan (please wait)...")
        except Exception:
            hydra_logger.logger.debug("Failed to request scan stop.", exc_info=True)

    def update_status(self, message):
        self.root.after(0, lambda: self.status_label.config(text=message))

    def update_progress(self, current, total):
        def _update():
            try:
                self.progress_bar['maximum'] = total
                self.progress_bar['value'] = current
                self.update_status("Scanning... ({}/{})".format(current, total))
            except Exception:
                pass
        self.root.after(0, _update)

    def add_result(self, result):
        self.root.after(0, lambda: self._add_result_to_view(result))

    def _add_result_to_view(self, result):
        self.scan_results.append(result)
        if self._result_matches_filters(result):
            self.insert_result_into_tree(result)

    def _result_matches_filters(self, result):
        filter_mode = self.filter_var.get()
        if filter_mode == "Detections Only" and not result.get('suspicious'):
            return False
        if filter_mode == "Clean Only" and result.get('suspicious'):
            return False
        q = (self.search_var.get() or '').strip().lower()
        if not q:
            return True
        hay = []
        hay.append(result.get('path', '') or '')
        hay.append(result.get('detection_name', '') or '')
        hay.append(result.get('md5', '') or '')
        for r in (result.get('flagging_reasons') or []):
            hay.append(str(r))
        hay_text = '\n'.join(hay).lower()
        return q in hay_text

    def insert_result_into_tree(self, result):
        tag = 'CLEAN'
        if result['status'] == 'Error' or result['status'] == 'Skipped':
            tag = 'ERROR'
        elif result['suspicious']:
            tag = 'MALICIOUS'
        score_val = result.get('suspicious_score', 0)
        score_text = str(int(score_val)) if isinstance(score_val, (int, float)) else str(score_val)

        # Normalize path for display (keeps tree consistent)
        display_path = os.path.normpath(result.get('path', 'N/A')) if result.get('path') else 'N/A'

        item_id = self.tree.insert('', 'end', values=(
            len(self.tree.get_children()) + 1,
            display_path,
            result.get('detection_name', 'N/A'),
            score_text,
            result.get('status', 'N/A')
        ), tags=(tag,))
        result['tree_id'] = item_id
        # also store normalized path back in the result so subsequent actions use it
        result['path'] = display_path

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        filter_mode = self.filter_var.get()
        if filter_mode == "All":
            filtered_results = self.scan_results
        elif filter_mode == "Detections Only":
            filtered_results = [r for r in self.scan_results if r.get('suspicious')]
        elif filter_mode == "Clean Only":
            filtered_results = [r for r in self.scan_results if not r.get('suspicious')]
        else:
            filtered_results = self.scan_results
        q = (self.search_var.get() or '').strip().lower()
        if q:
            def matches_q(r):
                hay = []
                hay.append(r.get('path', '') or '')
                hay.append(r.get('detection_name', '') or '')
                hay.append(r.get('md5', '') or '')
                for rr in (r.get('flagging_reasons') or []):
                    hay.append(str(rr))
                hay_text = '\n'.join(hay).lower()
                return q in hay_text
            filtered_results = [r for r in filtered_results if matches_q(r)]
        for result in filtered_results:
            self.insert_result_into_tree(result)

    def clear_search(self):
        self.search_var.set('')
        self.apply_filter()

    def manage_whitelist(self):
        try:
            self._open_whitelist_window()
        except Exception as e:
            hydra_logger.logger.error("Failed to open whitelist manager: {}".format(e), exc_info=True)

    def _open_whitelist_window(self):
        wl = load_whitelist()
        top = tk.Toplevel(self.root)
        top.title("Whitelist Manager")
        top.geometry("700x400")
        top.configure(bg="#2E2E2E")
        frm = ttk.Frame(top, padding=10)
        frm.pack(expand=True, fill='both')
        left = ttk.Frame(frm)
        left.pack(side=tk.LEFT, fill='both', expand=True)
        right = ttk.Frame(frm, width=200)
        right.pack(side=tk.RIGHT, fill='y')
        lblp = ttk.Label(left, text="Whitelisted Paths (substring match):")
        lblp.pack(anchor='w')
        self._wl_paths_lb = tk.Listbox(left, height=8)
        self._wl_paths_lb.pack(fill='x', pady=(0,10))
        lblm = ttk.Label(left, text="Whitelisted MD5s:")
        lblm.pack(anchor='w')
        self._wl_md5_lb = tk.Listbox(left, height=8)
        self._wl_md5_lb.pack(fill='x', pady=(0,10))
        for p in wl.get('paths', []):
            self._wl_paths_lb.insert(tk.END, p)
        for m in wl.get('md5s', []):
            self._wl_md5_lb.insert(tk.END, m)
        ent_frame = ttk.Frame(right, padding=5)
        ent_frame.pack(anchor='n')
        ttk.Label(ent_frame, text="Add path substring:").pack()
        self._wl_add_path = ttk.Entry(ent_frame, width=30)
        self._wl_add_path.pack(pady=5)
        ttk.Button(ent_frame, text="Add Path", command=self.add_whitelist_entry).pack(pady=2)
        ttk.Label(ent_frame, text="Add MD5:").pack(pady=(10,0))
        self._wl_add_md5 = ttk.Entry(ent_frame, width=30)
        self._wl_add_md5.pack(pady=5)
        ttk.Button(ent_frame, text="Add MD5", command=self.add_whitelist_entry).pack(pady=2)
        ttk.Separator(right, orient='horizontal').pack(fill='x', pady=10)
        ttk.Button(right, text="Remove Selected", command=self.remove_whitelist_entry).pack(pady=5)
        ttk.Button(right, text="Refresh", command=lambda: self.refresh_whitelist_view(top)).pack(pady=5)
        self._whitelist_window = top
        self._whitelist_window.protocol("WM_DELETE_WINDOW", lambda: (setattr(self, '_whitelist_window', None), top.destroy()))

    def add_whitelist_entry(self):
        try:
            wl = load_whitelist()
            p = (self._wl_add_path.get() or '').strip()
            m = (self._wl_add_md5.get() or '').strip()
            changed = False
            if p:
                if p not in wl.get('paths', []):
                    wl['paths'].append(p)
                    changed = True
            if m:
                if m not in wl.get('md5s', []):
                    wl['md5s'].append(m)
                    changed = True
            if changed:
                save_whitelist(wl)
            self._wl_add_path.delete(0, tk.END)
            self._wl_add_md5.delete(0, tk.END)
            self.refresh_whitelist_view(self._whitelist_window)
        except Exception as e:
            hydra_logger.logger.error("Failed to add whitelist entry: {}".format(e), exc_info=True)

    def remove_whitelist_entry(self):
        try:
            wl = load_whitelist()
            sel_p = list(self._wl_paths_lb.curselection())
            sel_m = list(self._wl_md5_lb.curselection())
            changed = False
            for i in reversed(sel_p):
                try:
                    val = self._wl_paths_lb.get(i)
                    wl['paths'].remove(val)
                    changed = True
                except Exception:
                    continue
            for i in reversed(sel_m):
                try:
                    val = self._wl_md5_lb.get(i)
                    wl['md5s'].remove(val)
                    changed = True
                except Exception:
                    continue
            if changed:
                save_whitelist(wl)
            self.refresh_whitelist_view(self._whitelist_window)
        except Exception as e:
            hydra_logger.logger.error("Failed to remove whitelist entry: {}".format(e), exc_info=True)

    def refresh_whitelist_view(self, win):
        if not win:
            return
        try:
            wl = load_whitelist()
            self._wl_paths_lb.delete(0, tk.END)
            self._wl_md5_lb.delete(0, tk.END)
            for p in wl.get('paths', []):
                self._wl_paths_lb.insert(tk.END, p)
            for m in wl.get('md5s', []):
                self._wl_md5_lb.insert(tk.END, m)
        except Exception as e:
            hydra_logger.logger.error("Failed to refresh whitelist UI: {}".format(e), exc_info=True)

    def show_context_menu(self, event):
        """
        Right-click handler. Selects row under mouse, updates context menu item states,
        then pops up the menu.
        """
        try:
            row_id = self.tree.identify_row(event.y)
            if row_id:
                try:
                    self.tree.selection_set(row_id)
                except Exception:
                    pass
                result = self.get_result_from_id(row_id)
            else:
                sel = list(self.tree.selection())
                result = self.get_result_from_id(sel[0]) if sel else None

            # Update context menu states
            try:
                for i in range((self.context_menu.index("end") or -1) + 1):
                    try:
                        label = self.context_menu.entrycget(i, "label")
                    except Exception:
                        label = None
                    if label == "Quarantine":
                        if result and (result.get('suspicious') or result.get('status') == 'Detection'):
                            self.context_menu.entryconfig(i, state='normal')
                        else:
                            self.context_menu.entryconfig(i, state='disabled')
                    if label in ("Copy Path", "Add path to whitelist"):
                        self.context_menu.entryconfig(i, state='normal' if result else 'disabled')
            except Exception:
                hydra_logger.logger.debug("Failed to update context menu state.", exc_info=True)

            try:
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.context_menu.grab_release()
        except Exception as e:
            hydra_logger.logger.debug("show_context_menu failed: %s", e, exc_info=True)

    def get_result_from_id(self, item_id):
        return next((r for r in self.scan_results if r.get('tree_id') == item_id), None)

    def quarantine_selected(self):
        if not self.tree.selection():
            return
        selected_id = self.tree.selection()[0]
        result = self.get_result_from_id(selected_id)
        if not result or not (result.get('suspicious') or result.get('status') == 'Detection'):
            return
        file_path = result['path']
        warning_msg = (
            "You are about to quarantine the following file:\n\n"
            "{}\n\n"
            "This action will attempt to:\n"
            "1. Terminate the associated process (if running).\n"
            "2. Move the file to a secure quarantine folder.\n\n"
            "Proceed?"
        ).format(file_path)
        if messagebox.askyesno("Confirm Quarantine", warning_msg, icon='warning'):
            try:
                success, message = quarantine.initiate_quarantine(file_path)
                if success:
                    result['status'] = 'Quarantined'
                    try:
                        values = list(self.tree.item(selected_id, 'values'))
                        values[4] = 'Quarantined'
                        self.tree.item(selected_id, values=values, tags=('QUARANTINED',))
                    except Exception:
                        pass
                    try:
                        md5 = result.get('md5') or compute_md5(file_path)
                        known = load_known_malware()
                        if md5:
                            e = known.get(md5, {})
                            e['quarantined'] = True
                            e['last_seen'] = datetime.datetime.utcnow().isoformat() + "Z"
                            known[md5] = e
                            save_known_malware(known)
                    except Exception:
                        hydra_logger.logger.debug("Failed to update known-malware quarantined flag.", exc_info=True)
                    messagebox.showinfo("Success", message)
                else:
                    messagebox.showerror("Quarantine Failed", message)
            except Exception as e:
                messagebox.showerror("Quarantine Error", "An unexpected error occurred: {}".format(e))

    def _context_copy_path(self):
        sel = list(self.tree.selection())
        if not sel:
            return
        result = self.get_result_from_id(sel[0])
        if not result:
            return
        try:
            # Normalize to native path format (converts forward slashes to backslashes on Windows)
            raw = result.get('path', '') or ''
            norm = os.path.normpath(raw)
            # If you prefer capital drive letter, uncomment:
            # if norm and len(norm) >= 2 and norm[1] == ':':
            #     norm = norm[0].upper() + norm[1:]
            self.root.clipboard_clear()
            self.root.clipboard_append(norm)
            messagebox.showinfo("Copied", "Path copied to clipboard:\n\n{}".format(norm))
        except Exception:
            hydra_logger.logger.debug("Failed to copy path to clipboard.", exc_info=True)
            messagebox.showerror("Error", "Failed to copy path.")

    def _context_add_whitelist(self):
        sel = list(self.tree.selection())
        if not sel:
            return
        result = self.get_result_from_id(sel[0])
        if not result:
            return
        try:
            wl = load_whitelist()
            p = result.get('path', '')
            if p and p not in wl.get('paths', []):
                wl['paths'].append(p)
                save_whitelist(wl)
                messagebox.showinfo("Whitelist", "Path added to whitelist.")
        except Exception as e:
            hydra_logger.logger.error("Failed to add to whitelist: {}".format(e), exc_info=True)
            messagebox.showerror("Whitelist Error", "Could not add path to whitelist.")

    def show_details(self):
        # Accept either the current selection or the row under the pointer
        sel = list(self.tree.selection())
        if not sel:
            y = self.tree.winfo_pointery() - self.tree.winfo_rooty()
            item_id = self.tree.identify_row(y)
            if not item_id:
                return
            selected_id = item_id
        else:
            selected_id = sel[0]

        result = self.get_result_from_id(selected_id)
        if not result:
            return
        score_val = result.get('suspicious_score', 'N/A')
        score_text = str(int(score_val)) if isinstance(score_val, (int, float)) else str(score_val)
        details_format = (
            "File: {path}\n"
            "Detection: {detection_name}\n"
            "Obfuscation Score: {score}\n"
            "Status: {status}\n\n"
            "MD5: {md5}\n"
            "First seen (if known): {first_seen}\n\n"
            "--- Detection Reasons ---\n"
        )
        md5 = result.get('md5')
        known = load_known_malware()
        known_entry = known.get(md5, {}) if md5 else {}
        details = details_format.format(
            path=result.get('path', 'N/A'),
            detection_name=result.get('detection_name', 'N/A'),
            score=score_text,
            status=result.get('status', 'N/A'),
            md5=md5 or "N/A",
            first_seen=known_entry.get('first_seen', 'N/A')
        )
        reasons = result.get('flagging_reasons', ['None'])
        details += "\n".join(reasons) if reasons else "No specific reasons available."
        top = tk.Toplevel(self.root)
        top.title("Obfuscation Analysis Details")
        top.geometry("700x500")
        top.configure(bg="#2E2E2E")
        txt = scrolledtext.ScrolledText(top, wrap=tk.WORD, bg='#1C1C1C', fg='#D3D3D3', font=('Consolas', 10))
        txt.pack(expand=True, fill='both', padx=10, pady=10)
        txt.insert(tk.END, details)
        txt.config(state=tk.DISABLED)

    def scan_finished(self, total_scanned, suspicious_found, duration_seconds=0.0):
        def _finish():
            self.scan_button.config(state=tk.NORMAL)
            self.progress_bar['value'] = 0
            try:
                d = int(duration_seconds or 0)
                formatted = str(datetime.timedelta(seconds=d))
            except Exception:
                formatted = "{}s".format(int(duration_seconds or 0))
            self.update_status("Hardcoded scan complete. Scanned: {}. Detections: {}. Time: {}".format(total_scanned, suspicious_found, formatted))
            try:
                history = load_scan_history()
                history.extend([_sanitize_result_for_persistence(r) for r in self.scan_results])
                history = history[-5000:]
                save_scan_history(history)
            except Exception:
                hydra_logger.logger.debug("Failed to persist final results.", exc_info=True)
            # update stats label
            try:
                self._update_stats_label()
            except Exception:
                pass
            # reset control buttons
            try:
                self.pause_button.config(state=tk.DISABLED)
                self.resume_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.DISABLED)
            except Exception:
                pass
        self.root.after(0, _finish)

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
