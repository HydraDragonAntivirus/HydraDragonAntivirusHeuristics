#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Unified Suspicious File Scanner with yarGen Logic
# Combines the parallel scanning framework of suspicious_file_scanner.py
# with the advanced string scoring and analysis engine of yarGen.py.
#

import glob
import logging
import math
import os
import re
import sys
import time
import traceback
import argparse
import shutil
import urllib.request
import binascii
import json
import gzip
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Any, Dict, List, Set, Optional, Counter as TypingCounter
from collections import Counter

import ctypes
from ctypes import wintypes

# Optional imports that some environments may not have
try:
    import lief
except ImportError:
    lief = None
try:
    import psutil
except ImportError:
    psutil = None
try:
    from tqdm import tqdm
except ImportError:
    # Dummy tqdm if not installed
    def tqdm(iterable, **kwargs):
        return iterable
try:
    import pefile
except ImportError:
    pefile = None
try:
    import capstone
except ImportError:
    capstone = None

# NLTK usage is best-effort
try:
    import nltk
    # Suppress verbose download output
    import io
    from contextlib import redirect_stdout
    with redirect_stdout(io.StringIO()):
        try:
            nltk.data.find('tokenizers/punkt')
        except nltk.downloader.DownloadError:
            nltk.download("punkt", quiet=True)
        try:
            nltk.data.find('corpora/words')
        except nltk.downloader.DownloadError:
            nltk.download("words", quiet=True)
    from nltk.corpus import words
    nltk_words: Set[str] = set(words.words())
except ImportError:
    nltk = None
    nltk_words = set()


# ------------------------------
# Global Configuration & Containers
# ------------------------------
SUSPICIOUS_THRESHOLD = 11  # Base score to be considered suspicious
SCAN_FOLDER = "."          # Default scan folder

# --- Global DB Containers ---
# These will be populated by load_good_dbs()
good_strings_db: TypingCounter[str] = Counter()
good_opcodes_db: Set[str] = set()
good_imphashes_db: Set[str] = set()
good_exports_db: Set[str] = set()
# yarGen-style special string sets, populated during analysis
base64strings: Dict[str, bytes] = {}
hexEncStrings: Dict[str, bytes] = {}
reversedStrings: Dict[str, str] = {}
stringScores: Dict[str, float] = {}

USE_OPCODES = False

# ------------------------------
# Regexes and Constants
# ------------------------------
ASCII_RE = re.compile(rb"[\x1f-\x7e]{6,}")
WIDE_RE = re.compile(rb"(?:[\x1f-\x7e][\x00]){6,}")
HEX_CAND_RE = re.compile(rb"([A-Fa-f0-9]{10,})")

REPO_URLS = {
    'good-opcodes-part1.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part1.db',
    'good-opcodes-part2.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part2.db',
    'good-opcodes-part3.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part3.db',
    'good-opcodes-part4.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part4.db',
    'good-opcodes-part5.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part5.db',
    'good-opcodes-part6.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part6.db',
    'good-opcodes-part7.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part7.db',
    'good-opcodes-part8.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part8.db',
    'good-opcodes-part9.db': 'https://www.bsk-consulting.de/yargen/good-opcodes-part9.db',
    'good-strings-part1.db': 'https://www.bsk-consulting.de/yargen/good-strings-part1.db',
    'good-strings-part2.db': 'https://www.bsk-consulting.de/yargen/good-strings-part2.db',
    'good-strings-part3.db': 'https://www.bsk-consulting.de/yargen/good-strings-part3.db',
    'good-strings-part4.db': 'https://www.bsk-consulting.de/yargen/good-strings-part4.db',
    'good-strings-part5.db': 'https://www.bsk-consulting.de/yargen/good-strings-part5.db',
    'good-strings-part6.db': 'https://www.bsk-consulting.de/yargen/good-strings-part6.db',
    'good-strings-part7.db': 'https://www.bsk-consulting.de/yargen/good-strings-part7.db',
    'good-strings-part8.db': 'https://www.bsk-consulting.de/yargen/good-strings-part8.db',
    'good-strings-part9.db': 'https://www.bsk-consulting.de/yargen/good-strings-part9.db',
    'good-exports-part1.db': 'https://www.bsk-consulting.de/yargen/good-exports-part1.db',
    'good-exports-part2.db': 'https://www.bsk-consulting.de/yargen/good-exports-part2.db',
    'good-exports-part3.db': 'https://www.bsk-consulting.de/yargen/good-exports-part3.db',
    'good-exports-part4.db': 'https://www.bsk-consulting.de/yargen/good-exports-part4.db',
    'good-exports-part5.db': 'https://www.bsk-consulting.de/yargen/good-exports-part5.db',
    'good-exports-part6.db': 'https://www.bsk-consulting.de/yargen/good-exports-part6.db',
    'good-exports-part7.db': 'https://www.bsk-consulting.de/yargen/good-exports-part7.db',
    'good-exports-part8.db': 'https://www.bsk-consulting.de/yargen/good-exports-part8.db',
    'good-exports-part9.db': 'https://www.bsk-consulting.de/yargen/good-exports-part9.db',
    'good-imphashes-part1.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part1.db',
    'good-imphashes-part2.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part2.db',
    'good-imphashes-part3.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part3.db',
    'good-imphashes-part4.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part4.db',
    'good-imphashes-part5.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part5.db',
    'good-imphashes-part6.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part6.db',
    'good-imphashes-part7.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part7.db',
    'good-imphashes-part8.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part8.db',
    'good-imphashes-part9.db': 'https://www.bsk-consulting.de/yargen/good-imphashes-part9.db',
}

# Logging setup
logging.basicConfig(
    filename="unified_scanner.log",
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


# =============================================================================
# UTILITY AND HELPER FUNCTIONS
# =============================================================================

def is_ascii_char(b: bytes, padding_allowed: bool = False) -> int:
    """Check if a byte represents a printable ASCII character."""
    o = ord(b)
    if padding_allowed:
        return 1 if (31 < o < 127) or o == 0 else 0
    else:
        return 1 if 31 < o < 127 else 0


def is_ascii_string(string: bytes, padding_allowed: bool = False) -> int:
    """Check if a byte string contains only printable ASCII characters."""
    for b in (i.to_bytes(1, sys.byteorder) for i in string):
        if not is_ascii_char(b, padding_allowed):
            return 0
    return 1


def is_base_64(s: str) -> bool:
    """Check if a string is a valid Base64 encoded string."""
    return (len(s) % 4 == 0) and re.match(r"^[A-Za-z0-9+/]+[=]{0,2}$", s) is not None


def is_hex_encoded(s: str, check_length: bool = True) -> bool:
    """Check if a string is hex encoded."""
    if re.match(r"^[A-Fa-f0-9]+$", s):
        return len(s) % 2 == 0 if check_length else True
    return False

def calculate_entropy(path: str) -> float:
    """Calculate Shannon entropy for a file."""
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
                    freq[b] += 1
        entropy = 0.0
        if total > 0:
            for f in freq:
                if f > 0:
                    p = f / total
                    entropy -= p * math.log2(p)
        return entropy
    except Exception as e:
        logging.debug("Entropy calc failed for %s: %s", path, e, exc_info=True)
        return 0.0

def is_likely_word(s: str) -> bool:
    """Return True if string is at least 3 chars and exists in NLTK words."""
    if not nltk_words:
        return False
    return len(s) >= 3 and s.lower() in nltk_words


# =============================================================================
# DATABASE MANAGEMENT FUNCTIONS
# =============================================================================

def load_good_dbs(db_path="./dbs", use_opcodes: bool = False):
    """
    Loads all known-good DBs safely and populates global containers.
    - Handles gzipped, plain json, and plain text line formats.
    - Populates 'good_strings_db' as a Counter for weighted scoring.
    - Populates other DBs as sets for fast membership checking.
    """
    global good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db
    good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = Counter(), set(), set(), set()

    if not os.path.exists(db_path):
        logging.warning("Database path does not exist, skipping DB load: %s", db_path)
        return

    files = sorted(glob.glob(os.path.join(db_path, "*.db")))
    if not files:
        logging.warning("No .db files found in %s", db_path)
        return

    print(f"Loading databases from: {db_path}")
    for p in files:
        bn = os.path.basename(p).lower()
        if "opcodes" in bn and not use_opcodes:
            continue

        db_data = None
        try:
            with gzip.open(p, "rt", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                try:
                    db_data = json.loads(content)
                except json.JSONDecodeError:
                    db_data = [line for line in content.splitlines() if line.strip()]
        except (gzip.BadGzipFile, IOError, EOFError):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    try:
                        db_data = json.loads(content)
                    except json.JSONDecodeError:
                        db_data = [line for line in content.splitlines() if line.strip()]
            except Exception as e:
                logging.error("Failed to load DB file %s: %s", p, e)
                continue
        except Exception as e:
            logging.error("Unhandled error loading DB file %s: %s", p, e)
            continue
        
        if not db_data:
            continue

        items = db_data if isinstance(db_data, list) else list(db_data.items())

        if "strings" in bn:
            # For strings, we need the counts for scoring, so use a Counter
            good_strings_db.update(dict(items) if isinstance(db_data, dict) else {i: 1 for i in items})
        elif "opcodes" in bn:
            good_opcodes_db.update(k for k,v in items) if isinstance(db_data, dict) else good_opcodes_db.update(items)
        elif "imphashes" in bn:
            good_imphashes_db.update(k for k,v in items) if isinstance(db_data, dict) else good_imphashes_db.update(items)
        elif "exports" in bn:
            good_exports_db.update(k for k,v in items) if isinstance(db_data, dict) else good_exports_db.update(items)

    logging.info(f"DBs loaded: {len(good_strings_db)} strings, {len(good_opcodes_db)} opcodes, "
                 f"{len(good_imphashes_db)} imphashes, {len(good_exports_db)} exports.")
    print(f"DBs loaded successfully.")


def update_databases(force: bool = False, db_dir: str = "./dbs", use_opcodes: bool = False):
    """Download yarGen DBs from the repository."""
    os.makedirs(db_dir, exist_ok=True)
    for filename, repo_url in REPO_URLS.items():
        if "opcodes" in filename and not use_opcodes:
            continue
        out_path = os.path.join(db_dir, filename)
        if os.path.exists(out_path) and not force:
            continue
        try:
            print(f"Downloading {filename}...")
            with urllib.request.urlopen(repo_url, timeout=30) as response, open(out_path, "wb") as out_file:
                shutil.copyfileobj(response, out_file)
            logging.info("Saved DB: %s", out_path)
        except Exception as e:
            logging.exception("Error downloading %s: %s", filename, e)


# =============================================================================
# CORE FILE ANALYSIS FUNCTIONS (string/opcode/PE extraction)
# =============================================================================

def extract_hex_strings(s: bytes) -> List[bytes]:
    """yarGen's hex string extraction logic."""
    strings = []
    hex_strings = HEX_CAND_RE.findall(s)
    for string in list(hex_strings):
        hex_strings += string.split(b'0000')
        hex_strings += string.split(b'0d0a')
    hex_strings = list(set(hex_strings))
    for string in hex_strings:
        for x in string.split(b'00'):
            if len(x) > 10:
                strings.append(x)
    for string in hex_strings:
        try:
            if len(string) % 2 != 0 or len(string) < 8 or b'0000' in string:
                continue
            dec = string.replace(b'00', b'')
            if is_ascii_string(dec, padding_allowed=False):
                strings.append(string)
        except Exception:
            pass
    return strings

def extract_strings(file_data: bytes) -> List[str]:
    """Extracts ASCII, UTF-16LE, and hex-encoded strings from file data."""
    cleaned_strings = set()
    if not file_data:
        return []

    # ASCII and hex
    strings_full = ASCII_RE.findall(file_data)
    strings_hex = extract_hex_strings(file_data)
    
    # UTF-16LE
    wide_strings_raw = WIDE_RE.findall(file_data)

    all_byte_strings = set(strings_full) | set(strings_hex)

    for string in all_byte_strings:
        try:
            s = string.replace(b'\\', b'\\\\').replace(b'"', b'\\"')
            cleaned_strings.add(s.decode('utf-8', errors='ignore'))
        except Exception:
            pass

    for ws in wide_strings_raw:
        try:
            # Prepend marker for scoring logic to identify wide strings
            decoded_ws = ws.decode('utf-16le', errors='ignore')
            cleaned_strings.add(f"UTF16LE:{decoded_ws}")
        except Exception:
            pass
            
    return list(cleaned_strings)

def extract_opcodes(file_data: bytes) -> List[str]:
    """Extracts opcodes from the entry point section of a PE/ELF file."""
    if not lief:
        return []
    opcodes = []
    try:
        binary = lief.parse(list(file_data)) # Use list(file_data) for better parsing resilience
        if not binary:
            return []
            
        ep = binary.entrypoint
        text = None

        if isinstance(binary, lief.PE.Binary):
            for sec in binary.sections:
                if sec.virtual_address + binary.imagebase <= ep < sec.virtual_address + binary.imagebase + sec.size:
                    text = bytes(sec.content)
                    break
        elif isinstance(binary, lief.ELF.Binary):
            for sec in binary.sections:
                if sec.virtual_address <= ep < sec.virtual_address + sec.size:
                    text = bytes(sec.content)
                    break
        
        if text:
            text_parts = re.split(b"[\x00]{3,}", text)
            for text_part in text_parts:
                if len(text_part) >= 8:
                    opcodes.append(binascii.hexlify(text_part[:16]).decode())
    except Exception as e:
        logging.debug("Opcode extraction failed: %s", e)
    return opcodes


def get_pe_info(file_data: bytes) -> tuple:
    """Extracts Imphash and exports from a PE file."""
    imphash, exports = "", []
    if not lief or not file_data or file_data[:2] != b"MZ":
        return imphash, exports
    try:
        binary = lief.parse(list(file_data))
        if isinstance(binary, lief.PE.Binary):
            imphash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE)
            if binary.has_exports:
                for entry in binary.exported_functions:
                    if entry.name:
                        exports.append(entry.name)
    except Exception as e:
        logging.debug("PE info extraction failed: %s", e)
    return imphash or "", exports

# =============================================================================
# SIGNATURE AND CAPSTONE ANALYSIS (for Triage)
# =============================================================================

class WinVerifyTrust_GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8)
    ]

WINTRUST_ACTION_GENERIC_VERIFY_V2 = WinVerifyTrust_GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.POINTER(WinVerifyTrust_GUID))
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID), ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", wintypes.LPVOID)
    ]

def check_valid_signature(file_path: str) -> dict:
    """Uses WinVerifyTrust to check for a valid Authenticode signature."""
    if sys.platform != 'win32':
        return {"is_valid": False, "status": "Not on Windows"}

    try:
        file_info = WINTRUST_FILE_INFO(
            cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
            pcwszFilePath=file_path
        )
        wtd = WINTRUST_DATA(
            cbStruct=ctypes.sizeof(WINTRUST_DATA),
            dwUnionChoice=1, # WTD_CHOICE_FILE
            pFile=ctypes.byref(file_info),
            dwUIChoice=2, # WTD_UI_NONE
            fdwRevocationChecks=0, # WTD_REVOKE_NONE
            dwStateAction=0 # WTD_STATEACTION_IGNORE
        )
        
        result = ctypes.windll.wintrust.WinVerifyTrust(
            None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd)
        )
        
        if result == 0:
            return {"is_valid": True, "status": "Valid"}
        else:
            return {"is_valid": False, "status": f"Invalid signature (Code: 0x{result & 0xFFFFFFFF:08X})"}
    except Exception as e:
        return {"is_valid": False, "status": f"Error: {e}"}

def analyze_with_capstone(pe, capstone_module) -> Dict[str, Any]:
    """Performs disassembly with Capstone to find packing indicators."""
    analysis = {"overall_analysis": {"is_likely_packed": False}, "error": None}
    if not capstone_module or not pe:
        return analysis

    try:
        machine = getattr(pe, "FILE_HEADER", None)
        if machine and machine.Machine == 0x014C:
             md = capstone_module.Cs(capstone_module.CS_ARCH_X86, capstone_module.CS_MODE_32)
        elif machine and machine.Machine == 0x8664:
             md = capstone_module.Cs(capstone_module.CS_ARCH_X86, capstone_module.CS_MODE_64)
        else:
            return analysis

        total_add, total_mov = 0, 0
        for section in pe.sections:
            code = section.get_data()
            if not code: continue
            
            # Simple heuristic: high add vs mov can indicate unpacking stub
            add_count = code.count(b'\x01') + code.count(b'\x83\xc0') # ADD reg, imm; ADD eax, imm
            mov_count = code.count(b'\x8b') + code.count(b'\xb8') # MOV reg, reg; MOV eax, imm
            total_add += add_count
            total_mov += mov_count
        
        if total_add > total_mov and total_mov > 0:
             analysis["overall_analysis"]["is_likely_packed"] = True

    except Exception as e:
        analysis["error"] = str(e)
    return analysis

# =============================================================================
# YARGEN SCORING ENGINE
# =============================================================================

def score_strings_yargen_style(strings: List[str], min_score_threshold: int = 0) -> Dict[str, Any]:
    """
    Analyzes a list of strings using yarGen's scoring logic.
    Returns a dictionary with top strings, suspicious percentage, and status.
    """
    global stringScores, base64strings, hexEncStrings, reversedStrings
    stringScores, base64strings, hexEncStrings, reversedStrings = {}, {}, {}, {}

    localStringScores = {}
    suspicious_count = 0
    
    for s_orig in strings:
        # yarGen's logic starts here
        goodstring = False
        goodcount = 0
        
        s = s_orig
        if s.startswith("UTF16LE:"):
            s = s[8:]

        # Check against goodware DB
        if s_orig in good_strings_db or s in good_strings_db:
            goodstring = True
            goodcount = good_strings_db.get(s_orig, 0) or good_strings_db.get(s, 0)
        
        score = (goodcount * -1) + 5 if goodstring else 0

        # Heuristic scoring (simplified from yarGen for clarity)
        if not goodstring:
            if re.search(r'(shell|powershell|invoke|download|execute|payload|encrypt|inject|credential)', s, re.I): score += 4
            if re.search(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b', s): score += 5
            if re.search(r'([A-Za-z]:\\|%appdata%|/tmp/|/var/|system32)', s, re.I): score += 3
            if re.search(r'\.(exe|dll|scr|bat|ps1|vbs)\b', s, re.I): score += 2
            if re.search(r'(rat\b|meterpreter|metasploit|katz|mimikatz|backdoor|implant)', s, re.I): score += 5
            if re.search(r'^(?:[A-Za-z0-9+/]{4}){10,}', s) and is_base_64(s): score += 6
            if len(s) > 20 and is_hex_encoded(re.sub(r'[^0-9a-fA-F]', '', s), False): score += 4
            if s[::-1] in good_strings_db:
                score += 10
                reversedStrings[s_orig] = s[::-1]

        # Encoding detection
        try:
            if len(s) > 8:
                for m_string in (s, s[1:], s[:-1], s + "=", s + "=="):
                    if is_base_64(m_string):
                        decoded = base64.b64decode(m_string, validate=True)
                        if is_ascii_string(decoded, padding_allowed=True):
                            score += 10
                            base64strings[s_orig] = decoded
                            break
                if is_hex_encoded(s):
                    decoded = bytes.fromhex(s)
                    if is_ascii_string(decoded, padding_allowed=True):
                        score += 8
                        hexEncStrings[s_orig] = decoded
        except Exception:
            pass
            
        localStringScores[s_orig] = score
        stringScores[s_orig] = score
        if score >= min_score_threshold:
            suspicious_count += 1
            
    # Compile results
    total_strings = len(strings)
    suspicious_percentage = (suspicious_count / total_strings) * 100.0 if total_strings > 0 else 0.0
    
    sorted_scores = sorted(localStringScores.items(), key=lambda kv: kv[1], reverse=True)
    top_strings = [
        {"string": s, "score": sc} for s, sc in sorted_scores if sc > min_score_threshold
    ][:50]
    
    status = "Unknown/Generic"
    if suspicious_percentage < 1 and total_strings > 100:
        status = "Likely Clean (very low suspicious string ratio)"
    elif suspicious_percentage > 30:
        status = "Potentially Malicious (high ratio of suspicious strings)"

    return {
        "top_strings": top_strings,
        "suspicious_percentage": suspicious_percentage,
        "total_strings": total_strings,
        "status": status,
    }


# =============================================================================
# MAIN FILE SCANNER LOGIC
# =============================================================================

def analyze_single_file(path: str) -> dict:
    """
    Analyzes a single file using a two-stage process: a lightweight triage
    followed by a deep analysis for suspicious files.
    """
    features = {
        "path": path, "size": 0, "is_executable": False,
        "suspicious": False, "suspicious_score": 0,
        "yargen_summary": {"status": "Not analyzed", "total_strings": 0},
        "error": None
    }

    pe_obj = None
    try:
        # --- Stage 1: Triage (Lightweight Checks) ---
        stats = os.stat(path)
        features["size"] = stats.st_size
        if features["size"] < 100 or features["size"] > 20 * 1024 * 1024:
            return features

        with open(path, "rb") as f:
            header = f.read(2)
        is_executable = features["is_executable"] = header == b'MZ'

        prelim_score = 0
        signature_valid = False
        
        if is_executable:
            sig = check_valid_signature(path)
            signature_valid = sig.get("is_valid", False)
            if not signature_valid:
                prelim_score += 4 if "invalid" in sig.get("status", "").lower() else 2
            
            if pefile and capstone:
                try:
                    pe_obj = pefile.PE(path, fast_load=True)
                    cap_analysis = analyze_with_capstone(pe_obj, capstone)
                    if cap_analysis.get("overall_analysis", {}).get("is_likely_packed"):
                        prelim_score += 3
                finally:
                    if pe_obj: pe_obj.close()
        
        entropy = calculate_entropy(path)
        if entropy > 7.5:
            prelim_score += 5 if not signature_valid else 2

        # --- Triage Gate ---
        LIGHT_ANALYSIS_THRESHOLD = max(1, int(SUSPICIOUS_THRESHOLD / 2))
        if prelim_score < LIGHT_ANALYSIS_THRESHOLD:
            features["yargen_summary"]["status"] = "Skipped (low triage score)"
            return features

        # --- Stage 2: Deep Analysis (Heavy Checks) ---
        with open(path, "rb") as fh:
            file_bytes = fh.read()
            
        extracted_strings = extract_strings(file_bytes)
        imphash, exports = get_pe_info(file_bytes)

        # Goodware DB checks
        score_adjustment = 0
        if imphash and imphash in good_imphashes_db:
             score_adjustment -= 10
        if exports and any(e in good_exports_db for e in exports):
             score_adjustment -= 5
        
        yargen_analysis = score_strings_yargen_style(extracted_strings)
        features["yargen_summary"] = yargen_analysis
        
        # Final score calculation
        final_score = prelim_score + score_adjustment
        if yargen_analysis["suspicious_percentage"] > 30:
            final_score += 5
        elif yargen_analysis["suspicious_percentage"] > 10:
            final_score += 2
            
        if USE_OPCODES and is_executable:
            opcodes = extract_opcodes(file_bytes)
            if opcodes:
                unique_opcodes = set(opcodes)
                bad_opcodes = len(unique_opcodes - good_opcodes_db)
                if bad_opcodes > len(unique_opcodes) / 2:
                    final_score += 3

        features["suspicious_score"] = int(max(0, final_score))
        if features["suspicious_score"] >= SUSPICIOUS_THRESHOLD:
            features["suspicious"] = True

    except Exception as exc:
        logging.error("Failed to analyze %s: %s", path, exc, exc_info=True)
        features["error"] = str(exc)
    finally:
        if pe_obj and not pe_obj.is_closed():
            pe_obj.close()
            
    return features


def scan_directory_parallel(directory: str, max_workers: Optional[int] = None) -> List[Dict[str, Any]]:
    """Scans a directory in parallel using a process pool."""
    results = []
    files = [os.path.join(root, f) for root, _, filenames in os.walk(directory) for f in filenames]

    if not files:
        print("No files found to scan.")
        return []

    workers = max_workers or os.cpu_count() or 1
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(analyze_single_file, f): f for f in files}
        
        # Use tqdm for progress bar
        for future in tqdm(as_completed(futures), total=len(files), desc="Scanning", unit="file"):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logging.error("Error processing file %s: %s", futures[future], e)
    
    return results


# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified file scanner with yarGen analysis engine.")
    parser.add_argument(
        "-m", "--malware-path",
        dest="scan_path",
        default=SCAN_FOLDER,
        help=f"Path to scan for files (default: {SCAN_FOLDER}).",
    )
    parser.add_argument(
        "--update-db",
        action="store_true",
        help="Download/update goodware DB files into ./dbs before scanning.",
    )
    parser.add_argument(
        "--use-opcodes",
        action="store_true",
        help="Enable opcode extraction and DB checks (CPU-intensive).",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=SUSPICIOUS_THRESHOLD,
        help=f"Suspicion score threshold (default: {SUSPICIOUS_THRESHOLD})."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging to console.",
    )
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Set globals from args
    USE_OPCODES = args.use_opcodes
    SUSPICIOUS_THRESHOLD = args.threshold
    SCAN_FOLDER = args.scan_path

    print("--- Unified File Scanner ---")
    
    # DB update and load
    if args.update_db:
        update_databases(force=True, use_opcodes=USE_OPCODES)
    
    load_good_dbs(use_opcodes=USE_OPCODES)
    
    # Run scan
    print(f"Starting scan on directory: {SCAN_FOLDER}")
    start_time = time.time()
    all_results = scan_directory_parallel(SCAN_FOLDER)
    end_time = time.time()
    
    suspicious_files = [r for r in all_results if r.get("suspicious")]
    
    # Print summary
    print("\n--- Scan Summary ---")
    print(f"Scan completed in {end_time - start_time:.2f} seconds.")
    print(f"Total files scanned: {len(all_results)}")
    print(f"Suspicious files found: {len(suspicious_files)}")
    
    if suspicious_files:
        print("\n--- Top Suspicious Files ---")
        # Sort by score, descending
        suspicious_files.sort(key=lambda x: x.get('suspicious_score', 0), reverse=True)
        
        for res in suspicious_files[:20]: # Show top 20
            yara_summary = res.get('yargen_summary', {})
            print(f"\nPath: {res['path']}")
            print(f"  Score: {res['suspicious_score']} (Threshold: {SUSPICIOUS_THRESHOLD})")
            print(f"  String Analysis: {yara_summary.get('status', 'N/A')}")
            print(f"    Suspicious Strings: {yara_summary.get('suspicious_percentage', 0.0):.1f}% of {yara_summary.get('total_strings', 0)}")
            
            top_strings = yara_summary.get('top_strings', [])
            if top_strings:
                print("    Top Scored Strings:")
                for ts in top_strings[:3]:
                     # Truncate long strings for display
                    display_str = ts['string'].replace('\n', '\\n').replace('\r', '\\r')
                    if len(display_str) > 80:
                        display_str = display_str[:77] + "..."
                    print(f"      - (Score: {ts['score']:.1f}) \"{display_str}\"")

    print("\nScan finished. Check unified_scanner.log for detailed logs.")

