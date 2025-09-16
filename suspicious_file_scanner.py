#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HydraScanner - Hardcoded Obfuscation Detection (patched)
This file is the full scanner GUI with persistent result storage ("remembering results")
and a simple known-malware store. The previous "make process critical" / BSOD behavior
has been removed; quarantine now relies on the quarantine module to safely handle termination
and moving files. The pe_feature_extractor import (get_cached_pe_features) is kept and used.
This patched version adds defensive checks and a safe runner for analyzer functions so
single-function failures won't convert the whole file into "Analysis-Error".
Compatible with Python 3.5+ and ReactOS where tkinter/psutil/quarantine are available.
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
import psutil

# --- Compatibility imports for tkinter ---
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext, messagebox, font
except ImportError:
    import Tkinter as tk
    import ttk
    import tkFileDialog as filedialog
    import ScrolledText as scrolledtext
    import tkMessageBox as messagebox
    import tkFont as font

# Import the PE feature extractor helper (kept per requirement)
try:
    from pe_feature_extractor import get_cached_pe_features
except ImportError:
    hydra_logger.logger.error("Could not import PE feature extractor. Make sure pe_feature_extractor.py is available.")
    raise

base_dir = os.path.dirname(os.path.abspath(__file__))

# --- Persistence files ---
_SCAN_HISTORY_FILE = os.path.join(base_dir, "scan_history.json")
_KNOWN_MALWARE_FILE = os.path.join(base_dir, "known_malware.json")
_persistence_lock = threading.RLock()

# --- Globals and Configuration ---
SUSPICIOUS_THRESHOLD = 43  # Increased threshold for hardcoded system
DETECTION_NAME = "HEUR:Win32.Susp.Obfuscated.gen"

SUSPICIOUS_DIRS = [
    os.environ.get('TEMP', ''),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads') if os.environ.get('USERPROFILE') else '',
    os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp') if os.environ.get('USERPROFILE') else ''
]

# --- Dynamic Startup Directory Location ---
STARTUP_DIRS = []
try:
    import ctypes
    from ctypes import wintypes
    CSIDL_STARTUP = 0x0007
    CSIDL_COMMON_STARTUP = 0x0018

    def get_special_folder_path(csidl):
        try:
            buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
            ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
            return buf.value
        except Exception as e:
            hydra_logger.logger.warning("Could not get special folder path for CSIDL {}: {}".format(csidl, e))
            return None

    user_startup = get_special_folder_path(CSIDL_STARTUP)
    if user_startup:
        STARTUP_DIRS.append(user_startup)
    common_startup = get_special_folder_path(CSIDL_COMMON_STARTUP)
    if common_startup:
        STARTUP_DIRS.append(common_startup)
except Exception as e:
    hydra_logger.logger.warning("Could not initialize dynamic startup directory search: {}".format(e))

# --- Utility: compute MD5 (used for remembering and known-malware keys) ---
def compute_md5(file_path):
    """Compute MD5 hash of a file; returns hex digest or None on error."""
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

# --- Persistence helpers (use default=str to help JSON-serialize numpy or other weird types) ---
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

# --- Small helper to ensure JSON-friendly value types in results (best-effort) ---
def _sanitize_result_for_persistence(r):
    try:
        sanitized = dict(r)
        # ensure basic fields are basic types
        if 'suspicious_score' in sanitized:
            try:
                # cast to float (or int)
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
    """Detect if a string appears obfuscated using various heuristics."""
    if not s or len(s) < 3:
        return False

    # Check for non-printable characters
    non_printable_count = sum(1 for c in s if c not in string.printable)
    if non_printable_count > len(s) * 0.3:  # More than 30% non-printable
        return True

    # Check for excessive special characters
    special_chars = sum(1 for c in s if c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`')
    if special_chars > len(s) * 0.4:  # More than 40% special characters
        return True

    # Check for patterns like base64 padding or hex patterns
    if re.search(r'[A-Za-z0-9+/]{20,}={0,2}$', s):  # Base64-like
        return True

    if re.search(r'^[0-9A-Fa-f]{16,}$', s):  # Long hex string
        return True

    # Check for reversed common strings
    common_words = ['kernel32', 'ntdll', 'advapi32', 'user32', 'shell32']
    reversed_s = s[::-1].lower()
    if any(word in reversed_s for word in common_words):
        return True

    # Check for mixed case in unusual patterns
    if re.search(r'[a-z][A-Z][a-z][A-Z]', s):
        return True

    return False

def calculate_string_entropy(s):
    """Calculate Shannon entropy for a string."""
    if not s:
        return 0

    # Get frequency of each character
    char_counts = {}
    for char in s:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy
    entropy = 0
    length = len(s)
    for count in char_counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy

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

    resources = pe_features.get('resources', [])

    large_resources = 0
    for resource in resources:
        res_size = resource.get('size', 0)
        if res_size > 1024 * 1024:  # > 1MB
            large_resources += 1

    if large_resources > 0:
        score += large_resources * 3
        reasons.append("{} large resources (>1MB each) (+{})".format(large_resources, large_resources * 3))

    if len(resources) > 50:
        score += 5
        reasons.append("Excessive number of resources: {} (+5)".format(len(resources)))

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

        if overlay_size > 100 * 1024:  # > 100KB
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
    """
    Run func(*args, **kwargs) and return (score, reasons).
    On exception, log full traceback and return (0, ["<name> error: ..."]).
    """
    try:
        result = func(*args, **kwargs)
        # normalize expected return types (score, reasons)
        if isinstance(result, tuple) and len(result) == 2:
            score, reasons = result
            try:
                # ensure types
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
            # unexpected return, treat as no score
            hydra_logger.logger.warning("Analyzer '%s' returned unexpected type: %s", name, type(result))
            return 0, []
    except Exception as e:
        tb = traceback.format_exc()
        hydra_logger.logger.error("Analysis function '%s' raised: %s\n%s", name, e, tb)
        return 0, ["{} analysis failed: {}".format(name, str(e))]

# --- Core Analysis Logic (with persistence hooks) ---
def _append_history_and_known(result):
    """Thread-safe store of scan result and known-malware update."""
    try:
        # Load, append, save history
        history = load_scan_history()
        sanitized = _sanitize_result_for_persistence(result)
        history.append(sanitized)
        if len(history) > 5000:
            history = history[-5000:]
        save_scan_history(history)

        # If suspicious, add/update known malware store by MD5
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

def analyze_single_file(path):
    """
    Analyzes a single file using hardcoded obfuscation detection.
    Stores results to persistent history and updates known-malware store.
    """
    analysis_result = {
        'path': path,
        'suspicious': False,
        'detection_name': "Clean",
        'suspicious_score': 0.0,
        'flagging_reasons': [],
        'status': 'Scanned',
        'md5': compute_md5(path)
    }

    try:
        # Defensive: ensure file still exists before processing
        if not os.path.exists(path):
            analysis_result['detection_name'] = "File missing"
            analysis_result['status'] = 'Skipped'
            _append_history_and_known(analysis_result)
            return analysis_result

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

        # Defensive: ensure pe_features is a mapping-like object
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

        # Use _safe_run for each analyzer so one failing analyzer won't mark whole file as Analysis-Error
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

        # Additional heuristics (wrapped defensively)
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

        # finalize
        analysis_result['suspicious_score'] = total_score
        analysis_result['flagging_reasons'] = all_reasons

        if total_score >= SUSPICIOUS_THRESHOLD:
            analysis_result.update({
                'suspicious': True,
                'detection_name': DETECTION_NAME,
                'status': 'Detection'
            })
            hydra_logger.logger.info("[Suspicious] File: {} | Score: {} | Reasons: {}".format(path, total_score, "; ".join(all_reasons)))
        else:
            analysis_result['detection_name'] = "Clean (Score: {})".format(total_score)

    except Exception as e:
        # This except should be rare because per-analyzer errors are isolated by _safe_run.
        hydra_logger.logger.error("Failed to analyze {}: {}".format(path, e), exc_info=True)
        analysis_result.update({
            'detection_name': "Analysis-Error",
            'flagging_reasons': [str(e)],
            'status': 'Error'
        })

    # persist result & known-malware entry if applicable
    try:
        _append_history_and_known(analysis_result)
    except Exception:
        hydra_logger.logger.debug("Failed to persist analysis result for {}".format(path), exc_info=True)

    return analysis_result

def scan_directory_parallel(directory, app_instance, max_workers=None):
    """Scan directory in parallel using hardcoded detection."""
    file_paths = []
    app_instance.update_status("Collecting files...")
    for root, _, files in os.walk(directory):
        for f in files:
            file_paths.append(os.path.join(root, f))

    total = len(file_paths)
    if total == 0:
        app_instance.scan_finished(0, 0)
        return

    workers = max_workers or 100
    processed_count = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(analyze_single_file, p): p for p in file_paths}
        for fut in as_completed(futures):
            p = futures[fut]
            processed_count += 1
            app_instance.update_progress(processed_count, total)
            try:
                res = fut.result()
                if res:
                    app_instance.add_result(res)
            except Exception as e:
                hydra_logger.logger.exception("Worker failed for {}: {}".format(p, e))

    detections = len([r for r in app_instance.scan_results if r.get('suspicious')])
    app_instance.scan_finished(total, detections)

# --- GUI Application ---
class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HydraScanner - Hardcoded Obfuscation Detection")
        self.root.geometry("1000x700")
        self.root.minsize(800, 500)

        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except Exception:
            pass
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
        self.scan_results = []
        self._create_widgets()

        # load persistent history into view (remember results)
        try:
            persisted = load_scan_history()
            # keep only last N for UI performance
            for r in persisted[-1000:]:
                r['tree_id'] = None
                self.scan_results.append(r)
            self.apply_filter()
        except Exception:
            hydra_logger.logger.debug("Failed to load persisted scan history.", exc_info=True)

    def _create_widgets(self):
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)

        self.scan_button = ttk.Button(top_frame, text="Select Directory & Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))

        self.filter_var = tk.StringVar(value="Detections Only")
        self.filter_all = ttk.Radiobutton(top_frame, text="All", variable=self.filter_var, value="All", command=self.apply_filter)
        self.filter_all.pack(side=tk.LEFT, padx=5)
        self.filter_detections = ttk.Radiobutton(top_frame, text="Detections Only", variable=self.filter_var, value="Detections Only", command=self.apply_filter)
        self.filter_detections.pack(side=tk.LEFT, padx=5)
        self.filter_clean = ttk.Radiobutton(top_frame, text="Clean Only", variable=self.filter_var, value="Clean Only", command=self.apply_filter)
        self.filter_clean.pack(side=tk.LEFT, padx=5)

        tree_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        tree_frame.pack(expand=True, fill='both')

        columns = ("#", "file_path", "detection", "score", "status")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')

        self.tree.heading("#", text="#", anchor='w')
        self.tree.heading("file_path", text="File Path", anchor='w')
        self.tree.heading("detection", text="Detection Name", anchor='w')
        self.tree.heading("score", text="Score", anchor='w')
        self.tree.heading("status", text="Status", anchor='w')

        self.tree.column("#", width=60, stretch=False)
        self.tree.column("file_path", width=450)
        self.tree.column("detection", width=200)
        self.tree.column("score", width=120, stretch=False, anchor='center')
        self.tree.column("status", width=100, stretch=False, anchor='center')

        self.tree.pack(side=tk.LEFT, expand=True, fill='both')

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill='y')

        self.tree.tag_configure('CLEAN', foreground='#8FBC8F')
        self.tree.tag_configure('SUSPICIOUS', foreground='#FFD700')
        self.tree.tag_configure('MALICIOUS', foreground='#FF6347')
        self.tree.tag_configure('ERROR', foreground='#D3D3D3')
        self.tree.tag_configure('QUARANTINED', foreground='#ADD8E6')

        self.context_menu = tk.Menu(self.root, tearoff=0, bg="#1C1C1C", fg="white")
        self.context_menu.add_command(label="Quarantine File", command=self.quarantine_selected)
        self.context_menu.add_command(label="Show Details", command=self.show_details)
        self.tree.bind("<Button-3>", self.show_context_menu)

        status_frame = ttk.Frame(self.root, padding="5 5 10 5")
        status_frame.pack(fill=tk.X)
        self.status_label = ttk.Label(status_frame, text="Ready - Hardcoded Obfuscation Detection", anchor='w')
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_bar = ttk.Progressbar(status_frame, orient='horizontal', mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True)

    def start_scan(self):
        directory = filedialog.askdirectory()
        if not directory:
            return

        self.scan_button.config(state=tk.DISABLED)
        self.tree.delete(*self.tree.get_children())
        self.scan_results.clear()
        self.status_label.config(text="Starting hardcoded scan in: {}".format(directory))

        scan_thread = threading.Thread(target=scan_directory_parallel, args=(directory, self))
        scan_thread.daemon = True
        scan_thread.start()

    def update_status(self, message):
        self.root.after(0, lambda: self.status_label.config(text=message))

    def update_progress(self, current, total):
        def _update():
            self.progress_bar['maximum'] = total
            self.progress_bar['value'] = current
            self.update_status("Scanning... ({}/{})".format(current, total))
        self.root.after(0, _update)

    def add_result(self, result):
        # ensure UI-visible update happens on main thread
        self.root.after(0, lambda: self._add_result_to_view(result))

    def _add_result_to_view(self, result):
        # append to in-memory list and apply current filter
        self.scan_results.append(result)
        if self.filter_var.get() == "All":
            self.insert_result_into_tree(result)
        elif self.filter_var.get() == "Detections Only" and result['suspicious']:
            self.insert_result_into_tree(result)
        elif self.filter_var.get() == "Clean Only" and not result['suspicious']:
            self.insert_result_into_tree(result)

    def insert_result_into_tree(self, result):
        tag = 'CLEAN'
        if result['status'] == 'Error' or result['status'] == 'Skipped':
            tag = 'ERROR'
        elif result['suspicious']:
            tag = 'MALICIOUS'

        score_val = result.get('suspicious_score', 0)
        score_text = str(int(score_val)) if isinstance(score_val, (int, float)) else str(score_val)

        item_id = self.tree.insert('', 'end', values=(
            len(self.tree.get_children()) + 1,
            result.get('path', 'N/A'),
            result.get('detection_name', 'N/A'),
            score_text,
            result.get('status', 'N/A')
        ), tags=(tag,))
        result['tree_id'] = item_id

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        filter_mode = self.filter_var.get()

        if filter_mode == "All":
            filtered_results = self.scan_results
        elif filter_mode == "Detections Only":
            filtered_results = [r for r in self.scan_results if r['suspicious']]
        elif filter_mode == "Clean Only":
            filtered_results = [r for r in self.scan_results if not r['suspicious']]
        else:
            filtered_results = self.scan_results

        for result in filtered_results:
            self.insert_result_into_tree(result)

    def show_context_menu(self, event):
        item_id = self.tree.identify_row(event.y)
        if item_id:
            self.tree.selection_set(item_id)
            result = self.get_result_from_id(item_id)
            if result and (result.get('suspicious') or result.get('status') == 'Detection'):
                try:
                    self.context_menu.tk_popup(event.x_root, event.y_root)
                finally:
                    self.context_menu.grab_release()

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
        # Updated warning: removed "make critical process" / BSOD clause.
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
                    # update tree row to show quarantined
                    try:
                        values = list(self.tree.item(selected_id, 'values'))
                        values[4] = 'Quarantined'
                        self.tree.item(selected_id, values=values, tags=('QUARANTINED',))
                    except Exception:
                        pass
                    # persist change in known-malware store
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

    def show_details(self):
        if not self.tree.selection():
            return
        selected_id = self.tree.selection()[0]
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
        # load known info if available
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

    def scan_finished(self, total_scanned, suspicious_found):
        def _finish():
            self.scan_button.config(state=tk.NORMAL)
            self.progress_bar['value'] = 0
            self.update_status("Hardcoded scan complete. Scanned: {}. Detections: {}.".format(total_scanned, suspicious_found))
            # save final UI-visible portion of history for quick reload next time
            try:
                # persist last 1000 results to history
                history = load_scan_history()
                # merge with current in-memory results (simple append)
                history.extend([_sanitize_result_for_persistence(r) for r in self.scan_results])
                # trim and save
                history = history[-5000:]
                save_scan_history(history)
            except Exception:
                hydra_logger.logger.debug("Failed to persist final results.", exc_info=True)
        self.root.after(0, _finish)

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
