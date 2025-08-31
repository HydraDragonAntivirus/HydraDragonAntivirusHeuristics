#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import io
import re
import gzip
import json
import math
import time
import glob
import base64
import shutil
import logging
import argparse
import binascii
from collections import Counter
from typing import Any, Dict, List, Set, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed
import psutil 
import pefile
import capstone
import lief
from tqdm import tqdm

# NLTK optional for "is_likely_word"
try:
    import nltk
    import io as _io
    from contextlib import redirect_stdout
    with redirect_stdout(_io.StringIO()):
        try:
            nltk.data.find('tokenizers/punkt')
        except Exception:
            nltk.download('punkt', quiet=True)
        try:
            nltk.data.find('corpora/words')
        except Exception:
            nltk.download('words', quiet=True)
    from nltk.corpus import words as _nltk_words
    nltk_words: Set[str] = set(_nltk_words.words())
except Exception:
    nltk = None
    nltk_words = set()

# Logging
logging.basicConfig(
    filename="suspicious_file_scanner.log",
    filemode="a",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# --------------------
# Config / Globals
# --------------------
SUSPICIOUS_THRESHOLD = 11
SCAN_FOLDER = "."
USE_OPCODES = False

# DB containers
good_strings_db: Counter = Counter()
good_opcodes_db: Set[str] = set()
good_imphashes_db: Set[str] = set()
good_exports_db: Set[str] = set()

# yarGen style result containers (populated per-run)
base64strings: Dict[str, bytes] = {}
hexEncStrings: Dict[str, bytes] = {}
reversedStrings: Dict[str, str] = {}
stringScores: Dict[str, float] = {}

# Candidate regexes
ASCII_RE = re.compile(rb"[\x1f-\x7e]{6,}")
WIDE_RE = re.compile(rb"(?:[\x1f-\x7e][\x00]){6,}")
HEX_CAND_RE = re.compile(rb"([A-Fa-f0-9]{10,})")

# Example REPO URLS (same as original snippet)
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

# Suspicious / system directories (used by capstone scanner)
SUSPICIOUS_DIRS = [
    os.environ.get('TEMP', ''),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp')
]
SYSTEM_ROOT = os.environ.get('SystemRoot', os.environ.get('WINDIR', r"C:\Windows"))
SYSTEM_DIRS = [
    os.path.join(SYSTEM_ROOT, 'System32'),
    os.path.join(SYSTEM_ROOT, 'SysWOW64'),
    os.path.join(SYSTEM_ROOT)
]
STARTUP_DIRS = [
    os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    os.path.join(os.environ.get('PROGRAMDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
]

# --------------------
# Utility functions
# --------------------
def is_ascii_char(b: bytes, padding_allowed: bool = False) -> int:
    o = b[0] if isinstance(b, (bytes, bytearray)) else ord(b)
    if padding_allowed:
        return 1 if (31 < o < 127) or o == 0 else 0
    else:
        return 1 if 31 < o < 127 else 0

def is_ascii_string(string: bytes, padding_allowed: bool = False) -> bool:
    try:
        for b in string:
            if not is_ascii_char(bytes([b]), padding_allowed):
                return False
        return True
    except Exception:
        return False

def is_base_64(s: str) -> bool:
    return (len(s) % 4 == 0) and re.match(r"^[A-Za-z0-9+/]+[=]{0,2}$", s) is not None

def is_hex_encoded(s: str, check_length: bool = True) -> bool:
    if re.match(r"^[A-Fa-f0-9]+$", s):
        return (len(s) % 2 == 0) if check_length else True
    return False

def calculate_entropy(path: str) -> float:
    freq = [0] * 256
    total = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk: break
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
    if not nltk_words:
        return False
    return len(s) >= 3 and s.lower() in nltk_words

# --------------------
# DB Management
# --------------------
def load_good_dbs(db_path: str = "./dbs", use_opcodes: bool = False):
    global good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db
    good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = Counter(), set(), set(), set()

    if not os.path.exists(db_path):
        logging.warning("Database path not found: %s", db_path)
        return
    files = sorted(glob.glob(os.path.join(db_path, "*.db")))
    if not files:
        logging.info("No DB files in %s", db_path)
        return

    for p in files:
        bn = os.path.basename(p).lower()
        if "opcodes" in bn and not use_opcodes:
            continue
        try:
            # try gzip then text
            try:
                with gzip.open(p, "rt", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except (gzip.BadGzipFile, OSError):
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            try:
                data = json.loads(content)
            except Exception:
                data = [line for line in content.splitlines() if line.strip()]
            if "strings" in bn:
                if isinstance(data, dict):
                    good_strings_db.update(data)
                else:
                    good_strings_db.update({s: 1 for s in data})
            elif "opcodes" in bn:
                if isinstance(data, dict):
                    good_opcodes_db.update(data.keys())
                else:
                    good_opcodes_db.update(data)
            elif "imphashes" in bn:
                if isinstance(data, dict):
                    good_imphashes_db.update(data.keys())
                else:
                    good_imphashes_db.update(data)
            elif "exports" in bn:
                if isinstance(data, dict):
                    good_exports_db.update(data.keys())
                else:
                    good_exports_db.update(data)
        except Exception as e:
            logging.warning("Failed to load DB %s: %s", p, e)
    logging.info("Loaded DBs: strings=%d opcodes=%d imphashes=%d exports=%d",
                 len(good_strings_db), len(good_opcodes_db), len(good_imphashes_db), len(good_exports_db))

def update_databases(force: bool = False, db_dir: str = "./dbs", use_opcodes: bool = False):
    os.makedirs(db_dir, exist_ok=True)
    for filename, url in REPO_URLS.items():
        if "opcodes" in filename and not use_opcodes:
            continue
        out = os.path.join(db_dir, filename)
        if os.path.exists(out) and not force:
            continue
        try:
            with __import__("urllib.request").request.urlopen(url, timeout=30) as resp, open(out, "wb") as fh:
                shutil.copyfileobj(resp, fh)
            logging.info("Downloaded DB %s", filename)
        except Exception as e:
            logging.warning("Failed to download %s: %s", filename, e)

# --------------------
# String/hex extraction (yarGen-like)
# --------------------
def extract_hex_strings(s: bytes) -> List[bytes]:
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
    cleaned = set()
    if not file_data:
        return []
    ascii_found = ASCII_RE.findall(file_data)
    hex_found = extract_hex_strings(file_data)
    wide_found = WIDE_RE.findall(file_data)

    all_byte_strings = set(ascii_found) | set(hex_found)
    for bs in all_byte_strings:
        try:
            s = bs.replace(b'\\', b'\\\\').replace(b'"', b'\\"')
            cleaned.add(s.decode('utf-8', errors='ignore'))
        except Exception:
            pass
    for ws in wide_found:
        try:
            dec = ws.decode('utf-16le', errors='ignore')
            cleaned.add(f"UTF16LE:{dec}")
        except Exception:
            pass
    return list(cleaned)

# --------------------
# PE/Capstone utilities
# --------------------
def get_pe_info(file_bytes: bytes) -> (str, List[str]):
    imphash, exports = "", []
    if not file_bytes or file_bytes[:2] != b'MZ':
        return imphash, exports
    if lief:
        try:
            binary = lief.parse(io.BytesIO(file_bytes))
            if isinstance(binary, lief.PE.Binary):
                try:
                    imphash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE)
                except Exception:
                    imphash = ""
                if binary.has_exports:
                    for e in binary.exported_functions:
                        if e.name: exports.append(e.name)
        except Exception:
            pass
    else:
        # fallback using pefile if available
        try:
            if pefile:
                pe = pefile.PE(data=file_bytes, fast_load=True)
                try:
                    imphash = getattr(pe, "get_imphash", lambda: "")()
                except Exception:
                    imphash = ""
                try:
                    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                        for exp in getattr(pe, 'DIRECTORY_ENTRY_EXPORT').symbols:
                            if exp.name:
                                exports.append(exp.name.decode(errors='ignore'))
                except Exception:
                    pass
        except Exception:
            pass
    return imphash or "", exports

def extract_opcodes_from_bytes(file_bytes: bytes) -> List[str]:
    try:
        parts = []
        if lief:
            try:
                binary = lief.parse(io.BytesIO(file_bytes))
                if binary:
                    ep = getattr(binary, "entrypoint", None)
                    if isinstance(binary, lief.PE.Binary):
                        for sec in binary.sections:
                            start = sec.virtual_address + binary.imagebase
                            if ep and start <= ep < start + sec.size:
                                raw = bytes(sec.content)
                                parts.append(binascii.hexlify(raw[:64]).decode())
                                break
            except Exception:
                pass
        if not parts:
            parts.append(binascii.hexlify(file_bytes[:128]).decode())
        return parts
    except Exception:
        return []

def analyze_with_capstone_pe(pe_obj) -> Dict[str, Any]:
    """
    Analyze a PE object using Capstone and return per-section and overall instruction stats.
    Detects potential packing heuristically via ADD vs MOV counts.
    """
    analysis = {
        "overall_analysis": {
            "is_likely_packed": False,
            "add_count": 0,
            "mov_count": 0,
            "total_instructions": 0
        },
        "sections": {},
        "error": None
    }

    if not capstone or not pe_obj or not pefile:
        return analysis

    try:
        # Determine architecture
        machine_type = getattr(getattr(pe_obj, "FILE_HEADER", None), "Machine", None)
        if machine_type == pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_I386', 0x014c):
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif machine_type == pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_AMD64', 0x8664):
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            return analysis

        total_add = 0
        total_mov = 0
        total_instructions = 0

        for section in pe_obj.sections:
            try:
                code = section.get_data()
                if not code:
                    continue

                base_addr = pe_obj.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                instructions = md.disasm(code, base_addr)

                counts = {}
                add_count = 0
                mov_count = 0
                section_total = 0

                for instr in instructions:
                    mnem = instr.mnemonic
                    counts[mnem] = counts.get(mnem, 0) + 1
                    section_total += 1
                    if mnem == "add":
                        add_count += 1
                    elif mnem == "mov":
                        mov_count += 1

                section_name = section.Name.decode(errors='ignore').strip('\x00')
                analysis["sections"][section_name] = {
                    "instruction_counts": counts,
                    "add_count": add_count,
                    "mov_count": mov_count,
                    "total_instructions": section_total,
                    "is_likely_packed": (add_count > mov_count) if section_total > 0 else False
                }

                total_add += add_count
                total_mov += mov_count
                total_instructions += section_total

            except Exception:
                continue

        # Overall aggregation
        analysis["overall_analysis"]["add_count"] = total_add
        analysis["overall_analysis"]["mov_count"] = total_mov
        analysis["overall_analysis"]["total_instructions"] = total_instructions
        analysis["overall_analysis"]["is_likely_packed"] = (total_add > total_mov) if total_instructions > 0 else False

    except Exception as e:
        analysis["error"] = str(e)

    return analysis

# --------------------
# WinVerifyTrust signature checking (robust handling)
# --------------------
import ctypes
from ctypes import wintypes

class WinVerifyTrust_GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

WINTRUST_ACTION_GENERIC_VERIFY = WinVerifyTrust_GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(WinVerifyTrust_GUID)),
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", ctypes.c_void_p),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0x00000000

_trust = None
try:
    _trust = ctypes.windll.wintrust
except Exception:
    _trust = None

# HRESULT constants
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0008
TRUST_E_PROVIDER_UNKNOWN     = 0x800B0001
CERT_E_UNTRUSTEDROOT         = 0x800B0109
TRUST_E_BAD_DIGEST           = 0x80096010
TRUST_E_CERT_SIGNATURE       = 0x80096004
NO_SIGNATURE_CODES = {TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN}

def _build_wtd_for(file_path: str) -> WINTRUST_DATA:
    fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
    wtd = WINTRUST_DATA()
    ctypes.memset(ctypes.byref(wtd), 0, ctypes.sizeof(wtd))
    wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wtd.dwUIChoice = WTD_UI_NONE
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE
    wtd.dwUnionChoice = WTD_CHOICE_FILE
    wtd.pFile = ctypes.pointer(fi)
    wtd.dwStateAction = WTD_STATEACTION_IGNORE
    return wtd

def verify_authenticode_signature(file_path: str) -> int:
    if not _trust:
        raise RuntimeError("WinVerifyTrust not available on this platform")
    wtd = _build_wtd_for(file_path)
    return _trust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY), ctypes.byref(wtd))

def check_valid_signature(file_path: str) -> dict:
    if sys.platform != "win32":
        return {"is_valid": False, "status": "Not on Windows"}
    try:
        res = verify_authenticode_signature(file_path)
        h = res & 0xFFFFFFFF
        if h == 0:
            return {"is_valid": True, "status": "Valid"}
        if h in NO_SIGNATURE_CODES:
            return {"is_valid": False, "status": "No signature"}
        if h == CERT_E_UNTRUSTEDROOT:
            return {"is_valid": False, "status": "Untrusted root"}
        if h == TRUST_E_BAD_DIGEST:
            return {"is_valid": False, "status": f"Fully invalid (bad digest) (HRESULT=0x{h:08X})"}
        if h == TRUST_E_CERT_SIGNATURE:
            return {"is_valid": False, "status": f"Fully invalid (cert signature verify failed) (HRESULT=0x{h:08X})"}
        return {"is_valid": False, "status": f"Invalid signature (HRESULT=0x{h:08X})"}
    except Exception as e:
        logging.debug("Signature check error for %s: %s", file_path, e)
        return {"is_valid": False, "status": str(e)}

# --------------------
# YarGen-style string scoring (fixed)
# --------------------
def score_strings_yargen_style(strings: List[str]) -> Dict[str, Any]:
    global stringScores, base64strings, hexEncStrings, reversedStrings, good_strings_db
    stringScores, base64strings, hexEncStrings, reversedStrings = {}, {}, {}, {}
    local_scores = {}
    total_unknown_weight = 0.0

    # Maximum possible score per string (adjust if you change scoring rules)
    max_score_per_string = 9  # base 1 + english 1 + base64 2 + hex 2 + decode 2 + reversed 1

    for s_orig in strings:
        s = s_orig
        if s.startswith("UTF16LE:"):
            s = s[8:]

        # Known in whitelist DB?
        known = s_orig in good_strings_db or s in good_strings_db
        score = 0 if known else 1  # baseline

        if not known:
            # English word
            if is_likely_word(s):
                score += 1

            # Base64
            if re.fullmatch(r'(?:[A-Za-z0-9+/]{4}){2,}(?:==|=)?', s) and is_base_64(s):
                score += 2

            # Hex
            hex_candidate = re.sub(r'[^0-9a-fA-F]', '', s)
            if len(hex_candidate) > 8 and is_hex_encoded(hex_candidate, False):
                score += 2

            # Base64 decode attempt
            try:
                for m_string in (s, s[1:], s[:-1], s + "=", s + "=="):
                    if is_base_64(m_string):
                        decoded = base64.b64decode(m_string, validate=True)
                        if is_ascii_string(decoded, padding_allowed=True):
                            score += 2
                            base64strings[s_orig] = decoded
                            break
            except Exception:
                pass

            # Hex decode attempt
            try:
                if is_hex_encoded(s):
                    decoded = bytes.fromhex(s)
                    if is_ascii_string(decoded, padding_allowed=True):
                        score += 2
                        hexEncStrings[s_orig] = decoded
            except Exception:
                pass

            # Reversed string detection
            rev = s[::-1]
            if rev in good_strings_db:
                score += 2
                reversedStrings[s_orig] = rev

        local_scores[s_orig] = score
        stringScores[s_orig] = score

        # Add normalized unknown weight (0–1) per string
        total_unknown_weight += min(score / max_score_per_string, 1.0)

    total_strings = len(strings)
    unknown_percentage = (total_unknown_weight / total_strings) * 100 if total_strings else 0.0

    sorted_scores = sorted(local_scores.items(), key=lambda kv: kv[1], reverse=True)
    top_unknowns = [{"string": s, "score": sc} for s, sc in sorted_scores if sc > 0][:50]

    # Status based on unknown percentage
    status = "Mostly Known"
    if unknown_percentage > 50:
        status = "Mostly Unknown"
    elif unknown_percentage > 20:
        status = "Partially Unknown"

    return {
        "top_unknowns": top_unknowns,
        "unknown_percentage": unknown_percentage,
        "total_strings": total_strings,
        "status": status
    }

# --------------------
# Runtime helpers
# --------------------
def is_running_pe(path: str) -> bool:
    try:
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

def is_in_suspicious_location_pe(path: str) -> bool:
    path_norm = os.path.normcase(path)
    for d in SUSPICIOUS_DIRS + SYSTEM_DIRS + STARTUP_DIRS:
        if d and os.path.normcase(d) in path_norm:
            return True
    return False

# --------------------
# Single-file analysis (no known-extension/filename lookups)
# --------------------
def analyze_single_file(path: str) -> dict:
    """
    Analyze a single file with PE, Capstone, entropy, runtime, signature checks.
    Phase 1: basic heuristics (entropy, packing, location, running, signature, opcodes)
    Phase 2: YarGen-style string scoring (only if phase1_score >= threshold)
    """
    features = {
        'path': path,
        'entropy': 0.0,
        'size': 0,
        'is_executable': False,
        'has_version_info': False,
        'signature_valid': False,
        'signature_status': "N/A",
        'capstone_analysis': None,
        'is_running': False,
        'in_suspicious_location': False,
        'age_days': 0,
        'suspicious_score': 0,
        'suspicious': False,
        'phase1_score': 0,
        'phase2_summary': None
    }

    try:
        stats = os.stat(path)
        features['size'] = stats.st_size
        features['age_days'] = (time.time() - stats.st_ctime) / (24 * 3600)
        features['entropy'] = calculate_entropy(path)

        pe = None
        try:
            pe = pefile.PE(path)
            features['is_executable'] = True
            features['has_version_info'] = hasattr(pe, 'VS_FIXEDFILEINFO') and getattr(pe, 'VS_FIXEDFILEINFO') is not None

            # Capstone analysis
            features['capstone_analysis'] = analyze_with_capstone_pe(pe)

        except pefile.PEFormatError:
            # Not a valid PE, skip executable-specific
            return features
        finally:
            if pe:
                try:
                    pe.close()
                except Exception:
                    pass

        # Signature check
        try:
            sig = check_valid_signature(path)
            features['signature_valid'] = sig.get('is_valid', False)
            features['signature_status'] = sig.get('status', "N/A")
        except Exception:
            pass

        # Runtime/location checks
        features['is_running'] = is_running_pe(path)
        features['in_suspicious_location'] = is_in_suspicious_location_pe(path)

        # --------------------
        # Phase 1 scoring
        # --------------------
        phase1 = 0
        cap = features.get('capstone_analysis', {}).get('overall_analysis', {})

        if cap.get('is_likely_packed'):
            phase1 += 3
        if features['entropy'] > 7.5:
            phase1 += 5 if not features['signature_valid'] else 2
        if features['age_days'] < 1:
            phase1 += 2
        if 'temp' in path.lower() or 'cache' in path.lower():
            phase1 += 2
        if features['is_executable'] and not features['has_version_info'] and not features['signature_valid']:
            phase1 += 1
        if features['is_executable'] and not features['signature_valid']:
            if features['signature_status'] == "Untrusted root":
                phase1 += 4
            else:
                phase1 += 2
        if features['in_suspicious_location']:
            phase1 += 2
        if features['is_running']:
            phase1 += 3
        if features['signature_valid']:
            phase1 = max(phase1 - 3, 0)

        # --------------------
        # Opcode scoring
        # --------------------
        if USE_OPCODES and features['is_executable']:
            try:
                with open(path, "rb") as fh:
                    file_bytes = fh.read()
                opcodes = extract_opcodes_from_bytes(file_bytes)
                for op in opcodes:
                    if op in good_opcodes_db:
                        phase1 -= 1
                    else:
                        phase1 += 1
            except Exception:
                pass

        features['phase1_score'] = phase1
        features['suspicious_score'] = phase1
        features['suspicious'] = phase1 >= SUSPICIOUS_THRESHOLD

        if features['suspicious']:
            logging.info(f"[Phase 1] Suspicious detected: {path} | Score: {phase1}")

            # --------------------
            # Phase 2: YarGen string scoring
            # --------------------
            if features['suspicious']:
                try:
                    with open(path, "rb") as fh:
                        file_data = fh.read()
                    strings = extract_strings(file_data)
                    yargen_summary = score_strings_yargen_style(strings)  # uses global good_strings_db
                    features['phase2_summary'] = yargen_summary
                    logging.info(f"[Phase 2] YarGen summary for {path}: {yargen_summary}")

                    # --------------------
                    # Adjust suspicious score using unknown percentage
                    # --------------------
                    unknown_pct = yargen_summary.get("unknown_percentage", 0.0)
                    if unknown_pct < 20.0:
                        # Mostly known, reduce phase1_score to avoid false positives
                        features['suspicious_score'] = max(features['phase1_score'] // 2, 0)
                        features['suspicious'] = features['suspicious_score'] >= SUSPICIOUS_THRESHOLD
                    elif unknown_pct < 50.0:
                        # Partially unknown, slightly reduce
                        features['suspicious_score'] = max(int(features['phase1_score'] * 0.75), 0)
                        features['suspicious'] = features['suspicious_score'] >= SUSPICIOUS_THRESHOLD
                    else:
                        # Mostly unknown, keep full score
                        features['suspicious_score'] = features['phase1_score']
                        features['suspicious'] = features['suspicious_score'] >= SUSPICIOUS_THRESHOLD

                except Exception as e:
                    logging.warning(f"[Phase 2] Failed for {path}: {e}")

    except Exception as e:
        logging.error(f"Failed to analyze {path}: {e}")
        features['error'] = str(e)

    return features

# --------------------
# Directory scanning (parallel) - updated signature
# --------------------
def scan_directory_parallel(directory: str, max_workers: Optional[int] = None):
    results = []
    file_paths = []
    for root, _, files in os.walk(directory):
        for f in files:
            file_paths.append(os.path.join(root, f))
    total = len(file_paths)
    if total == 0:
        print("No files to scan.")
        return []

    workers = max_workers or (os.cpu_count() or 1)
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(analyze_single_file, p): p for p in file_paths}
        for fut in tqdm(as_completed(futures), total=total, desc="Scanning", unit="file"):
            p = futures[fut]
            try:
                res = fut.result()
                results.append(res)
            except Exception as e:
                logging.exception("Worker failed for %s: %s", p, e)
    return results

# --------------------
# CLI / main
# --------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Suspicious file scanner")
    parser.add_argument("-m", "--malware-path", dest="scan_path", default=SCAN_FOLDER, help="Directory to scan")
    parser.add_argument("--update-db", action="store_true", help="Download DBs before scanning")
    parser.add_argument("--use-opcodes", action="store_true", help="Enable opcode DB checks (cpu-heavy)")
    parser.add_argument("-t", "--threshold", type=int, default=SUSPICIOUS_THRESHOLD, help="Suspicion threshold")
    args = parser.parse_args()

    USE_OPCODES = bool(args.use_opcodes)
    SUSPICIOUS_THRESHOLD = int(args.threshold)
    SCAN_FOLDER = args.scan_path

    print("--- Suspicious file scanner ---")
    if args.update_db:
        update_databases(force=True, use_opcodes=USE_OPCODES)
    load_good_dbs(use_opcodes=USE_OPCODES)
    print(f"Starting scan: {SCAN_FOLDER}")

    start = time.time()
    results = scan_directory_parallel(SCAN_FOLDER)
    dur = time.time() - start

    suspicious = [r for r in results if r.get("suspicious")]
    print("\n--- Scan Summary ---")
    print(f"Completed in {dur:.2f}s. Files scanned: {len(results)} Suspicious: {len(suspicious)}")
    # Top suspicious files
    if suspicious:
        suspicious.sort(key=lambda x: x.get("suspicious_score", 0), reverse=True)
        print("\nTop suspicious files:")
        for r in suspicious[:20]:
            ysum = r.get("phase2_summary") or {}  # <- Use empty dict if None
            print(f"{r['path']}\n  Score: {r['suspicious_score']}  Sig: {r.get('signature_status','N/A')}  Strings suspicious: {ysum.get('unknown_percentage',0):.1f}% ({ysum.get('total_strings',0)})")
            top = ysum.get("top_unknowns") or []  # <- Use empty list if None
            if top:
                for ts in top[:3]:
                    disp = ts['string'].replace("\n","\\n").replace("\r","\\r")
                    if len(disp) > 80: disp = disp[:77] + "..."
                    print(f"    - ({ts['score']:.1f}) \"{disp}\"")
    print("Done. See log for details.")
