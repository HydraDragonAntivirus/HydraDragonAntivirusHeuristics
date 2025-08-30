#!/usr/bin/env python
# -*- coding: utf-8 -*-

import glob
import logging
import math
import os
import re
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Any, Dict, List, Set, Optional

import ctypes
import binascii
import lief
import psutil
from ctypes import wintypes
from tqdm import tqdm

import argparse
import shutil
import urllib.request

# Optional imports that some environments may not have
try:
    import pefile
except Exception:
    pefile = None

try:
    import capstone
except Exception:
    capstone = None

# NLTK usage is best-effort
try:
    import nltk
    try:
        nltk.download("punkt", quiet=True)
    except Exception:
        pass
    try:
        nltk.download("words", quiet=True)
    except Exception:
        pass
    from nltk.corpus import words  # type: ignore
    nltk_words = set(words.words())
except Exception:
    nltk = None
    words = None  # type: ignore
    nltk_words = set()

# Basic configuration
SCAN_FOLDER = "D:\\datas2\\data2"
SUSPICIOUS_THRESHOLD = 11

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

# ===============================
# Regexes for string extraction (yarGen style) - now actually used
# ===============================
ASCII_RE = re.compile(rb"[\x1f-\x7e]{6,}")  # ASCII strings length >=6
WIDE_RE = re.compile(rb"(?:[\x1f-\x7e][\x00]){6,}")  # UTF-16LE wide strings length >=6
HEX_CAND_RE = re.compile(rb"([A-Fa-f0-9]{10,})")  # Hex-like substrings length >=10

PE_STRINGS_FILE = "./3rdparty/strings.xml"

KNOWN_IMPHASHES = {
    "a04dd9f5ee88d7774203e0a0cfa1b941": "PsExec",
    "2b8c9d9ab6fefc247adaf927e83dcea6": "RAR SFX variant",
}

RELEVANT_EXTENSIONS = [
    ".asp", ".vbs", ".ps", ".ps1", ".tmp", ".bas", ".bat", ".cmd", ".com", ".cpl",
    ".crt", ".dll", ".exe", ".msc", ".scr", ".sys", ".vb", ".vbe", ".vbs",
    ".wsc", ".wsf", ".wsh", ".input", ".war", ".jsp", ".php", ".asp", ".aspx",
    ".psd1", ".psm1", ".py",
]

# Small helper sets (populated by load_good_dbs)
base64strings: Set[str] = set()
hexEncStrings: Set[str] = set()
reversedStrings: Set[str] = set()
good_opcodes_db: Set[str] = set()

# Logging setup
logging.basicConfig(
    filename="scanner.log",
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def get_abs_path(filename: str) -> str:
    """Return absolute path relative to this file."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def get_files(folder: str, not_recursive: bool):
    """Yield files from folder, optionally non-recursive."""
    if not_recursive:
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            if os.path.isdir(file_path):
                continue
            yield file_path
    else:
        for root, _dirs, files in os.walk(folder, topdown=False):
            for name in files:
                file_path = os.path.join(root, name)
                yield file_path


def extract_hex_strings(s: bytes):
    strings = []
    hex_strings = re.findall(b"([a-fA-F0-9]{10,})", s)
    for string in list(hex_strings):
        hex_strings += string.split(b"0000")
        hex_strings += string.split(b"0d0a")
        hex_strings += re.findall(
            b"((?:0000|002[a-f0-9]|00[3-9a-f][0-9a-f]){6,})", string, re.IGNORECASE
        )
    hex_strings = list(set(hex_strings))
    # ASCII Encoded Strings
    for string in hex_strings:
        for x in string.split(b"00"):
            if len(x) > 10:
                try:
                    strings.append(x.decode('utf-8', errors='ignore'))
                except Exception:
                    strings.append(str(x))
    # WIDE Encoded Strings
    for string in hex_strings:
        try:
            if len(string) % 2 != 0 or len(string) < 8:
                continue
            if b"0000" in string:
                continue
            dec = string.replace(b"00", b"")
            if is_ascii_string(dec, padding_allowed=False):
                try:
                    strings.append(dec.decode('utf-8', errors='ignore'))
                except Exception:
                    strings.append(str(dec))
        except Exception:
            traceback.print_exc()
    return strings


def is_ascii_char(b: bytes, padding_allowed: bool = False) -> int:
    if padding_allowed:
        if (ord(b) < 127 and ord(b) > 31) or ord(b) == 0:
            return 1
    else:
        if ord(b) < 127 and ord(b) > 31:
            return 1
    return 0


def is_ascii_string(string: bytes, padding_allowed: bool = False) -> int:
    for b in [i.to_bytes(1, sys.byteorder) for i in string]:
        if padding_allowed:
            if not ((ord(b) < 127 and ord(b) > 31) or ord(b) == 0):
                return 0
        else:
            if not (ord(b) < 127 and ord(b) > 31):
                return 0
    return 1


def is_base_64(s: str) -> bool:
    return (len(s) % 4 == 0) and re.match(r"^[A-Za-z0-9+/]+[=]{0,2}$", s) is not None


def is_hex_encoded(s: str, check_length: bool = True) -> bool:
    if re.match(r"^[A-Fa-f0-9]+$", s):
        if check_length:
            return len(s) % 2 == 0
        return True
    return False


def extract_strings(file_data: bytes) -> List[str]:
    """Faster string extraction using precompiled regexes (ASCII, wide, hex candidates).

    This replaces the older multi-pass approach and aims to reduce duplicate
    decoding/reads. It returns a de-duplicated list of strings (order preserved).
    """
    results: List[str] = []
    seen = set()
    try:
        # ASCII matches
        for m in ASCII_RE.findall(file_data):
            try:
                s = m.decode('utf-8', errors='ignore')
            except Exception:
                s = str(m)
            if s and s not in seen:
                seen.add(s)
                results.append(s)

        # UTF-16LE wide matches
        for m in WIDE_RE.findall(file_data):
            try:
                s = m.decode('utf-16le', errors='ignore')
            except Exception:
                try:
                    s = m.decode('utf-8', errors='ignore')
                except Exception:
                    s = str(m)
            if s and s not in seen:
                seen.add(s)
                results.append(s)

        # Hex candidate matches -> try to extract readable sequences
        for m in HEX_CAND_RE.findall(file_data):
            try:
                if isinstance(m, bytes):
                    hex_bytes = m
                else:
                    hex_bytes = m.encode()
                hex_strings = extract_hex_strings(hex_bytes)
                for hs in hex_strings:
                    if hs and hs not in seen:
                        seen.add(hs)
                        results.append(hs)
            except Exception:
                continue

    except Exception:
        logging.debug("Error extracting strings (regex path)", exc_info=True)
    return results


def extract_opcodes(file_data: bytes) -> list:
    opcodes = []
    try:
        binary = lief.parse(file_data)
        ep = binary.entrypoint
        text = None
        if isinstance(binary, lief.PE.Binary):
            for sec in binary.sections:
                try:
                    if (
                        sec.virtual_address + binary.imagebase
                        <= ep
                        < sec.virtual_address + binary.imagebase + sec.virtual_size
                    ):
                        content = sec.content
                        if isinstance(content, (bytes, bytearray)):
                            text = bytes(content)
                        else:
                            text = bytes(content)
                        break
                except Exception:
                    continue
        elif isinstance(binary, lief.ELF.Binary):
            for sec in binary.sections:
                try:
                    if sec.virtual_address <= ep < sec.virtual_address + sec.size:
                        content = sec.content
                        if isinstance(content, (bytes, bytearray)):
                            text = bytes(content)
                        else:
                            text = bytes(content)
                        break
                except Exception:
                    continue

        if text is not None:
            text_parts = re.split(b"[\x00]{3,}", text)
            for text_part in text_parts:
                if text_part == b"" or len(text_part) < 8:
                    continue
                opcodes.append(
                    binascii.hexlify(text_part[:16]).decode(encoding="ascii")
                )
    except Exception:
        logging.debug("Opcode extraction failed", exc_info=True)
    return opcodes


def get_pe_info(file_data: bytes) -> tuple:
    imphash = ""
    exports: list = []
    try:
        if not file_data or file_data[:2] != b"MZ":
            return imphash, exports
    except Exception:
        return imphash, exports

    binary = None
    try:
        binary = lief.parse(file_data)
    except Exception:
        try:
            binary = lief.parse(list(file_data))
        except Exception:
            binary = None

    if binary is None:
        return imphash, exports

    try:
        try:
            imphash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE)
        except Exception:
            try:
                imphash = binary.imphash
            except Exception:
                imphash = ""
        if imphash is None:
            imphash = ""
    except Exception:
        imphash = ""

    try:
        expobj = None
        try:
            expobj = binary.get_export()
        except Exception:
            expobj = None

        if expobj:
            for entry in getattr(expobj, "entries", []) or []:
                try:
                    name = entry.name
                    if name is None:
                        continue
                    if isinstance(name, (bytes, bytearray)):
                        exports.append(name.decode("utf-8", errors="ignore"))
                    else:
                        exports.append(str(name))
                except Exception:
                    continue
    except Exception:
        pass

    return imphash, exports


def calculate_entropy(path: str) -> float:
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
    except Exception:
        logging.debug("Entropy calc failed for %s", path, exc_info=True)
        return 0.0


def load_good_dbs(dbs_dir: str = "./dbs"):
    """Load good-* DBs from a directory into memory sets, including exports.

    - Expects newline-separated plaintext files in ./dbs/.
    - For opcodes, normalizes by removing whitespace and lowercasing.
    - For imphashes, adds to KNOWN_IMPHASHES dict as key -> filename (or empty).
    """
    global good_opcodes_db, base64strings, hexEncStrings, reversedStrings, KNOWN_IMPHASHES, KNOWN_EXPORTS
    good_opcodes_db = set()
    base64strings = set()
    hexEncStrings = set()
    reversedStrings = set()
    KNOWN_IMPHASHES = {}
    KNOWN_EXPORTS = set()

    if not os.path.isdir(dbs_dir):
        logging.info("DBs directory not found: %s", dbs_dir)
        return

    for path in glob.glob(os.path.join(dbs_dir, "*")):
        bn = os.path.basename(path).lower()
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
        except Exception:
            logging.exception("Failed reading DB file %s", path)
            continue

        if "opcodes" in bn:
            for ln in lines:
                good_opcodes_db.add(ln.replace(" ", "").lower())
        elif "strings" in bn:
            for ln in lines:
                if is_base_64(ln):
                    base64strings.add(ln)
                elif is_hex_encoded(ln, check_length=False):
                    hexEncStrings.add(ln.lower())
                else:
                    reversedStrings.add(ln)
        elif "imphash" in bn or "imphashes" in bn:
            for ln in lines:
                KNOWN_IMPHASHES[ln.lower()] = bn
        elif "exports" in bn:
            for ln in lines:
                KNOWN_EXPORTS.add(ln.lower())

    logging.info(
        "Loaded good DBs: opcodes=%d base64=%d hexEnc=%d reversed=%d imphashes=%d exports=%d",
        len(good_opcodes_db),
        len(base64strings),
        len(hexEncStrings),
        len(reversedStrings),
        len(KNOWN_IMPHASHES),
        len(KNOWN_EXPORTS),
    )

def is_likely_word(s: str) -> bool:
    """Return True if string is at least 3 chars and exists in NLTK words."""
    return len(s) >= 3 and s.lower() in nltk_words

def check_file_against_good_dbs(file_path, file_data=None):
    """
    Scan a single file like parse_sample_dir, extract strings/opcodes/imphash/exports,
    and return the known-good match percentage.
    """
    try:
        # Read file if data not provided
        if file_data is None:
            with open(file_path, 'rb') as f:
                file_data = f.read()
    except Exception:
        print(f"[-] Cannot read file {file_path}")
        return 0.0

    # Extract strings
    strings = extract_strings(file_data)

    # Extract opcodes if enabled
    opcodes = extract_opcodes(file_data)

    # Compute imphash and exports
    imphash, exports = get_pe_info(file_data)

    # Compute match against known-good DBs
    total_markers = 0
    matches = 0

    # --- IMPHASH ---
    if KNOWN_IMPHASHES:
        total_markers += 1
        if imphash and imphash.lower() in KNOWN_IMPHASHES:
            matches += 1

    # --- EXPORTS ---
    if KNOWN_EXPORTS:
        total_markers += len(KNOWN_EXPORTS)
        for exp in exports:
            if exp.lower() in KNOWN_EXPORTS:
                matches += 1

    # --- OPCODES ---
    if good_opcodes_db:
        total_markers += len(good_opcodes_db)
        for op in opcodes:
            if op.replace(" ", "").lower() in good_opcodes_db:
                matches += 1

    # --- STRINGS ---
    string_dbs = [db for db in (base64strings, hexEncStrings, reversedStrings) if db]
    if string_dbs:
        strings_filtered = [s for s in strings if is_likely_word(s)]
        for db in string_dbs:
            total_markers += len(db)
            for s in strings_filtered:
                s_l = s.lower()
                if s in db or s_l in db:
                    matches += 1

    # Compute final percentage
    return (matches / total_markers * 100) if total_markers > 0 else 0.0

def analyze_with_capstone(pe, capstone_module) -> Dict[str, Any]:
    analysis = {
        "overall_analysis": {
            "total_instructions": 0,
            "add_count": 0,
            "mov_count": 0,
            "is_likely_packed": None,
        },
        "sections": {},
        "error": None,
    }

    try:
        if not capstone_module:
            analysis["error"] = "capstone module not available"
            return analysis

        if pe.FILE_HEADER.Machine == 0x014C:
            md = capstone_module.Cs(
                capstone_module.CS_ARCH_X86, capstone_module.CS_MODE_32
            )
        elif pe.FILE_HEADER.Machine == 0x8664:
            md = capstone_module.Cs(
                capstone_module.CS_ARCH_X86, capstone_module.CS_MODE_64
            )
        else:
            analysis["error"] = "Unsupported architecture."
            return analysis

        total_add_count = 0
        total_mov_count = 0
        grand_total_instructions = 0

        for section in pe.sections:
            try:
                section_name = section.Name.decode(errors="ignore").strip("\x00")
            except Exception:
                section_name = str(section.Name)
            code = section.get_data()
            base_address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

            instruction_counts = {}
            total_instructions_in_section = 0

            if not code:
                analysis["sections"][section_name] = {
                    "instruction_counts": {},
                    "total_instructions": 0,
                    "add_count": 0,
                    "mov_count": 0,
                    "is_likely_packed": False,
                }
                continue

            instructions = md.disasm(code, base_address)
            for i in instructions:
                mnemonic = i.mnemonic
                instruction_counts[mnemonic] = instruction_counts.get(mnemonic, 0) + 1
                total_instructions_in_section += 1

            add_count = instruction_counts.get("add", 0)
            mov_count = instruction_counts.get("mov", 0)

            total_add_count += add_count
            total_mov_count += mov_count
            grand_total_instructions += total_instructions_in_section

            analysis["sections"][section_name] = {
                "instruction_counts": instruction_counts,
                "total_instructions": total_instructions_in_section,
                "add_count": add_count,
                "mov_count": mov_count,
                "is_likely_packed": (
                    add_count > mov_count if total_instructions_in_section > 0 else False
                ),
            }

        analysis["overall_analysis"]["total_instructions"] = grand_total_instructions
        analysis["overall_analysis"]["add_count"] = total_add_count
        analysis["overall_analysis"]["mov_count"] = total_mov_count
        analysis["overall_analysis"]["is_likely_packed"] = (
            total_add_count > total_mov_count if grand_total_instructions > 0 else False
        )

    except Exception as exc:
        logging.error("Capstone disassembly failed: %s", exc)
        analysis["error"] = str(exc)

    return analysis


# WinVerifyTrust / Authenticode constants, types and setup
class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_byte)),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", ctypes.c_void_p),
    ]


PCCERT_CONTEXT = ctypes.POINTER(CERT_CONTEXT)


class WinVerifyTrust_GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


WINTRUST_ACTION_GENERIC_VERIFY_V2 = WinVerifyTrust_GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(WinVerifyTrust_GUID)),
    ]

# Windows type aliases for use in structures
WORD   = ctypes.c_ushort     # 16-bit
DWORD  = ctypes.c_uint32     # 32-bit unsigned
BOOL   = ctypes.c_int        # 32-bit signed (BOOL in WinAPI)
HANDLE = ctypes.c_void_p     # pointer-sized handle
LPVOID = ctypes.c_void_p

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]

# UI and revocation options
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0x00000000

# Load WinTrust DLL
_wintrust = ctypes.windll.wintrust

TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0008
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
CERT_E_UNTRUSTEDROOT = 0x800B0109
NO_SIGNATURE_CODES = {TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN}


def _build_wtd_for(file_path: str) -> WINTRUST_DATA:
    """Internal helper to populate a WINTRUST_DATA for the given file."""
    file_info = WINTRUST_FILE_INFO(
        ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None
    )
    wtd = WINTRUST_DATA()
    ctypes.memset(ctypes.byref(wtd), 0, ctypes.sizeof(wtd))
    wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wtd.dwUIChoice = WTD_UI_NONE
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE
    wtd.dwUnionChoice = WTD_CHOICE_FILE
    wtd.pFile = ctypes.pointer(file_info)
    wtd.dwStateAction = WTD_STATEACTION_IGNORE
    return wtd


def verify_authenticode_signature(file_path: str) -> int:
    wtd = _build_wtd_for(file_path)
    return _wintrust.WinVerifyTrust(
        None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd)
    )


def check_valid_signature(file_path: str) -> dict:
    TRUST_E_BAD_DIGEST = 0x80096010
    TRUST_E_CERT_SIGNATURE = 0x80096004

    try:
        result = verify_authenticode_signature(file_path)
        hresult = result & 0xFFFFFFFF

        if hresult == 0:
            return {"is_valid": True, "status": "Valid"}
        if hresult in NO_SIGNATURE_CODES:
            return {"is_valid": False, "status": "No signature"}
        if hresult == CERT_E_UNTRUSTEDROOT:
            return {"is_valid": False, "status": "Untrusted root"}
        if hresult == TRUST_E_BAD_DIGEST:
            status = f"Fully invalid (bad digest / signature mismatch) (HRESULT=0x{hresult:08X})"
            logging.warning("[Signature] %s: %s", file_path, status)
            return {"is_valid": False, "status": status}
        if hresult == TRUST_E_CERT_SIGNATURE:
            status = f"Fully invalid (certificate signature verification failed) (HRESULT=0x{hresult:08X})"
            logging.warning("[Signature] %s: %s", file_path, status)
            return {"is_valid": False, "status": status}

        status = f"Invalid signature (HRESULT=0x{hresult:08X})"
        logging.warning("[Signature] %s: %s", file_path, status)
        return {"is_valid": False, "status": status}

    except Exception as ex:
        logging.error("[Signature] check failed for %s: %s", file_path, ex)
        return {"is_valid": False, "status": str(ex)}


def is_running_pe(path: str) -> bool:
    try:
        for proc in psutil.process_iter(["exe", "name"]):
            try:
                exe = proc.info.get("exe")
                if exe and os.path.normcase(exe) == os.path.normcase(path):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return False


def _simple_yargen_scores(strings: List[str]) -> Dict[str, Any]:
    """
    A yarGen-inspired scoring function.
    Returns:
      {
        "yargen_strings": [top suspicious strings...],
        "yargen_suspicious_percentage": float,
        "total_strings": int,
        "status": "Likely Clean"|"Potentially Malicious"|...,
        "scores": { string: score, ... }
      }
    This is intentionally conservative and fast.
    """
    analysis = {
        "yargen_strings": [],
        "yargen_suspicious_percentage": 0.0,
        "total_strings": 0,
        "status": "Not Analyzed",
        "scores": {},
    }
    try:
        total = len(strings)
        analysis["total_strings"] = total
        if total == 0:
            analysis["status"] = "No strings found"
            return analysis

        scores = {}
        suspicious_count = 0

        # Precompile few regexes used often
        ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
        base64_re = re.compile(r'^(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
        hexhash_re = re.compile(r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b')

        for s in strings:
            s_l = s.lower()
            score = 0.0

            # quick length filter
            if len(s) < 6:
                scores[s] = score
                continue

            # Penalize very common-looking noise
            if re.search(r'^[\-\_\.0-9]+$', s) or len(set(s)) == 1:
                score -= 5

            # suspicious keywords (like yarGen)
            if re.search(r'(shell|powershell|invoke|download|execute|payload|encrypt|inject|token|credential|creds|net use|schtasks|rundll32|cmd\.exe|whoami|bitsadmin|Invoke-Expression)', s, re.IGNORECASE):
                score += 4

            # suspicious phrases that often appear in malware
            if re.search(r'(bypass|encodedcommand|frombase64string|memoryloadlibrary|downloadfile|wget|curl|base64decode|execv|system32|appdata|%appdata%)', s, re.IGNORECASE):
                score += 3

            # IP addresses / ports
            if ip_re.search(s):
                score += 5

            # base64 blobs
            if base64_re.match(s) or is_base_64(s):
                score += 6

            # Hex-encoded or big hex string
            if is_hex_encoded(re.sub(r'[^0-9a-fA-F]', '', s), check_length=False):
                score += 4

            # common hash indicators
            if hexhash_re.search(s):
                score += 2

            # file paths, registry, temp
            if re.search(r'([A-Za-z]:\\|%appdata%|/tmp/|/var/)', s, re.IGNORECASE):
                score += 3

            # commands and script markers
            if re.search(r'(\bwget\b|\bcurl\b|powershell -|invoke-expression|EncodedCommand|-nop\b|-w hidden\b|-command\b|iex\b)', s, re.IGNORECASE):
                score += 4

            # suspicious extensions or exe references
            if re.search(r'\.(exe|dll|scr|bat|ps1)\b', s, re.IGNORECASE):
                score += 2

            # RAT / malware keywords
            if re.search(r'(rat\b|meterpreter|metasploit|katz|katz|payload|reverse shell|bind shell|backdoor|implant)', s, re.IGNORECASE):
                score += 5

            # tokens, credentials, passwords
            if re.search(r'(password|passwd|token|auth|cookie|credential|creds|username|user|pass)', s, re.IGNORECASE):
                score += 3

            # suspicious punctuation combos (e.g. arrows, ! marks used in logs)
            if re.search(r'(-->|!!!|<<<|>>>)', s):
                score += 2

            # prefer strings that contain dictionary words (reduce false positives)
            if is_likely_word(s) or any(w.isalpha() and len(w) >= 3 and w.lower() in nltk_words for w in re.split(r'\W+', s) if nltk_words):
                score += 0.5

            # small heuristic: extremely high entropy strings (no spaces, many chars) => likely encoded
            # approximate by fraction of non-alnum characters
            non_alnum = sum(1 for ch in s if not ch.isalnum())
            if len(s) > 12 and (non_alnum / len(s)) < 0.05 and len(set(s)) > (len(s) // 4):
                # likely an encoded/packed blob or long random string
                score += 1.5

            scores[s] = score
            if score >= 4.0:
                suspicious_count += 1

        # sort top suspicious strings
        sorted_by_score = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        top_strings = [t[0] for t in sorted_by_score if t[1] > 0][:50]

        suspicious_percentage = (suspicious_count / total) * 100.0

        analysis["yargen_strings"] = top_strings[:50]
        analysis["yargen_suspicious_percentage"] = suspicious_percentage
        analysis["scores"] = {k: v for k, v in sorted_by_score[:200]}
        if suspicious_percentage < 1 and total > 100:
            analysis["status"] = "Likely Clean (very low suspicious string ratio)"
        elif suspicious_percentage > 30:
            analysis["status"] = "Potentially Malicious (high ratio of suspicious strings)"
        else:
            analysis["status"] = "Unknown/Generic"
    except Exception as exc:
        logging.error("yarGen scoring failed: %s", exc)
        analysis["status"] = f"Error during string analysis: {exc}"
    return analysis


def analyze_yargen_strings_from_list(strings: List[str]) -> Dict[str, Any]:
    """
    Wrapper to keep compatibility with original name. Uses the conservative yarGen-style scorer above.
    """
    return _simple_yargen_scores(strings)

def analyze_single_file(path: str) -> Dict[str, Any]:
    """Analyze a single file with Capstone disassembly and basic checks.

    Key change: extract strings once and reuse them for both "good db" checks
    and yara-like string analysis. yarGen-like analysis is executed *only* if
    the file's heuristic suspicious_score >= SUSPICIOUS_THRESHOLD.
    """
    features = {
        "path": path,
        "entropy": 0.0,
        "size": 0,
        "is_executable": False,
        "has_version_info": False,
        "signature_valid": False,
        "signature_status": "N/A",
        "capstone_analysis": None,
        "is_running": False,
        "age_days": 0,
        "extension": "",
        "suspicious_score": 0,
        "suspicious": False,
        "known_good_percent": 0.0,
        "unknown": False,   # <-- added default
    }

    try:
        # Basic FS stats
        stats = os.stat(path)
        features["size"] = stats.st_size
        features["age_days"] = (time.time() - stats.st_ctime) / (24 * 3600)
        features["entropy"] = calculate_entropy(path)

        filename_lc = os.path.basename(path).lower()
        ext = os.path.splitext(filename_lc)[1].lstrip(".")
        features["extension"] = ext

        # Read file bytes once for all binary checks
        file_bytes = b""
        try:
            with open(path, "rb") as fh:
                file_bytes = fh.read()
        except Exception:
            logging.debug("Failed to read file bytes for %s", path, exc_info=True)

        # Extract strings once and reuse
        strings = extract_strings(file_bytes) if file_bytes else []

        # Check known-good DBs as percentage
        try:
            features["known_good_percent"] = check_against_good_dbs_percentage(
                path, file_data=file_bytes, precomputed_strings=strings
            )
        except Exception:
            logging.debug("known_good_percent check failed for %s", path, exc_info=True)

        pe_obj = None
        try:
            if pefile:
                pe_obj = pefile.PE(path)
                features["is_executable"] = True
                features["has_version_info"] = (
                    hasattr(pe_obj, "VS_FIXEDFILEINFO") and pe_obj.VS_FIXEDFILEINFO is not None
                )
                features["capstone_analysis"] = analyze_with_capstone(pe_obj, capstone)
        except Exception:
            features["is_executable"] = features.get("is_executable", False)
            logging.debug("PE analysis failed for %s", path, exc_info=True)
        finally:
            if pe_obj:
                try:
                    pe_obj.close()
                except Exception:
                    pass

        if features["is_executable"]:
            try:
                sig = check_valid_signature(path)
                features["signature_valid"] = sig.get("is_valid", False)
                features["signature_status"] = sig.get("status", "N/A")
            except Exception:
                logging.debug("Signature check failed for %s", path, exc_info=True)
            features["is_running"] = is_running_pe(path)

        # Score heuristics (conservative)
        score = 0
        if features.get("capstone_analysis") and features["capstone_analysis"].get(
            "overall_analysis", {}
        ).get("is_likely_packed"):
            score += 3
        if features.get("entropy", 0) > 7.5:
            score += 5 if not features.get("signature_valid") else 2
        if features.get("age_days", 0) < 1:
            score += 2
        if "temp" in path.lower() or "cache" in path.lower():
            score += 2
        if features["is_executable"] and not features.get("has_version_info") and not features.get(
            "signature_valid"
        ):
            score += 1
        if features["is_executable"] and not features.get("signature_valid"):
            score += 4 if features.get("signature_status") == "Untrusted root" else 2
        if features.get("signature_valid"):
            score = max(score - 3, 0)
        if features.get("is_running"):
            score += 3
        if ext == "":
            score += 2

        # Adjust score based on known-good percentage (cap reduction)
        if features.get("known_good_percent", 0) > 0:
            reduction = score * min(features["known_good_percent"] / 100, 0.5)
            score = max(score - reduction, 0)

        features["suspicious_score"] = score
        features["suspicious"] = score >= SUSPICIOUS_THRESHOLD

        # Mark unknownness (only if suspicious)
        if features["suspicious"]:
            is_good = features.get("known_good_percent", 0) > 0
            is_signed = features.get("signature_valid", False)
            if not is_good and not is_signed:
                features["unknown"] = True
            else:
                features["unknown"] = False

        # Only run yarGen-like analysis if file is suspicious
        if features["suspicious"]:
            try:
                yargen_analysis = analyze_yargen_strings_from_list(strings)
                features["yargen_summary"] = yargen_analysis
                # Optional: bump score if yarGen finds lots of suspicious strings
                try:
                    if yargen_analysis.get("yargen_suspicious_percentage", 0) > 30:
                        features["suspicious_score"] += 3
                except Exception:
                    pass
            except Exception:
                logging.debug("YarGen-like analysis failed for %s", path, exc_info=True)
        else:
            features["yargen_summary"] = {
                "status": "Not analyzed (below suspicious threshold)",
                "total_strings": len(strings),
            }

    except Exception as exc:
        logging.error("Failed to analyze %s: %s", path, exc)
        features["error"] = str(exc)

    return features

def scan_directory_parallel(directory: str, max_workers: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Scan a directory in parallel using ProcessPoolExecutor (one process per CPU by default).
    Returns a list of feature dictionaries (same shape as before).
    """
    suspicious_results = []
    files = []
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    total_files = len(files)
    logging.info(
        "Scanning directory (parallel with Processes): %s, total files=%d",
        directory,
        total_files,
    )

    # Default to CPU count if not provided
    workers = max_workers or os.cpu_count() or 1

    # Use ProcessPoolExecutor (each analyze_single_file runs in its own process)
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(analyze_single_file, f): f for f in files}
        # Use as_completed to iterate as jobs finish
        for future in tqdm(as_completed(futures),
                           total=total_files,
                           desc="Scanning",
                           unit="file"):
            try:
                result = future.result()
                if result.get("suspicious"):
                    logging.warning(
                        "Suspicious file detected: %s (score=%d, unknown=%s, known_good_percent=%.1f%%)",
                        result["path"],
                        result.get("suspicious_score", -1),
                        result.get("unknown", False),
                        result.get("known_good_percent", 0.0),
                    )
                suspicious_results.append(result)
            except Exception as e:
                logging.error("Error during analysis of %s: %s", futures.get(future), e)

    return suspicious_results

def generate_general_condition(file_info: dict):
    conditions = []
    pe_module_neccessary = False
    try:
        magic_headers = []
        file_sizes = []
        imphashes = []
        for file_path in file_info:
            if "magic" not in file_info[file_path]:
                continue
            magic = file_info[file_path]["magic"]
            size = file_info[file_path]["size"]
            imphash = file_info[file_path]["imphash"]

            if magic not in magic_headers and magic != "":
                magic_headers.append(magic)
            if size not in file_sizes:
                file_sizes.append(size)
            if imphash not in imphashes and imphash != "":
                imphashes.append(imphash)

        if len(magic_headers) <= 5:
            magic_string = " or ".join(get_uint_string(h) for h in magic_headers)
            if " or " in magic_string:
                conditions.append("( {0} )".format(magic_string))
            else:
                conditions.append("{0}".format(magic_string))

        if len(file_sizes) > 0:
            conditions.append(get_file_range(max(file_sizes)))

        if len(imphashes) == 1:
            conditions.append("pe.imphash() == \"{0}\"".format(imphashes[0]))
            pe_module_neccessary = True

        condition_string = " and ".join(conditions)
    except Exception:
        logging.exception("Error while generating general condition")
        condition_string = ""
    return condition_string, pe_module_neccessary


def get_strings(string_elements):
    strings = {
        "ascii": [],
        "wide": [],
        "base64 encoded": [],
        "hex encoded": [],
        "reversed": [],
    }
    try:
        _ = base64strings
    except NameError:
        base64strings = set()
    try:
        _ = hexEncStrings
    except NameError:
        hexEncStrings = set()
    try:
        _ = reversedStrings
    except NameError:
        reversedStrings = set()

    for i, string in enumerate(string_elements):
        try:
            if isinstance(string, bytes):
                string = string.decode("utf-8", errors="ignore")
        except Exception:
            pass

        if string[:8] == "UTF16LE:":
            string = string[8:]
            strings["wide"].append(string)
        elif string in base64strings:
            strings["base64 encoded"].append(string)
        elif string in hexEncStrings:
            strings["hex encoded"].append(string)
        elif string in reversedStrings:
            strings["reversed"].append(string)
        else:
            strings["ascii"].append(string)

    return strings


def filter_opcode_set(opcode_set):
    pref_opcodes = [" 34 ", "ff ff ff "]
    useful_set = []
    pref_set = []

    for opcode in opcode_set:
        if opcode in good_opcodes_db:
            logging.debug("Skipping good opcode: %s", opcode)
            continue

        formatted_opcode = get_opcode_string(opcode)

        set_in_pref = False
        for pref in pref_opcodes:
            if pref in formatted_opcode:
                pref_set.append(formatted_opcode)
                set_in_pref = True
        if set_in_pref:
            continue

        useful_set.append(get_opcode_string(opcode))

    useful_set = pref_set + useful_set
    return useful_set[:50]


def get_opcode_string(opcode):
    return " ".join(opcode[i : i + 2] for i in range(0, len(opcode), 2))


def get_uint_string(magic):
    if len(magic) == 2:
        return "uint8(0) == 0x{0}{1}".format(magic[0], magic[1])
    if len(magic) == 4:
        return "uint16(0) == 0x{2}{3}{0}{1}".format(
            magic[0], magic[1], magic[2], magic[3]
        )
    return ""


def get_file_range(size):
    size_string = ""
    try:
        max_size_b = size * 1
        if max_size_b < 1024:
            max_size_b = 1024
        max_size = int(max_size_b / 1024)
        max_size_kb = max_size
        if len(str(max_size)) == 2:
            max_size = int(round(max_size, -1))
        elif len(str(max_size)) == 3:
            max_size = int(round(max_size, -2))
        elif len(str(max_size)) == 4:
            max_size = int(round(max_size, -3))
        elif len(str(max_size)) >= 5:
            max_size = int(round(max_size, -3))
        size_string = "filesize < {0}KB".format(max_size)
        logging.debug(
            "File Size Eval: SampleSize (b): %s SizeWithMultiplier (b/Kb): %s / %s RoundedSize: %s",
            str(size),
            str(max_size_b),
            str(max_size_kb),
            str(max_size),
        )
    except Exception:
        logging.exception("File range calc failed")
    return size_string


# -----------------------
# Database update helper + Main execution
# -----------------------

def update_databases(force: bool = False, db_dir: str = "./dbs"):
    """Download REPO_URLS into db_dir.

    - If force is False, only download missing files (resume-safe).
    - If force is True, re-download all files.
    """
    try:
        if not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    except Exception:
        logging.exception("Error creating db dir %s", db_dir)
        return

    for filename, repo_url in REPO_URLS.items():
        out_path = os.path.join(db_dir, filename)
        if os.path.exists(out_path) and not force:
            logging.info("DB already present, skipping: %s", out_path)
            continue
        try:
            logging.info("Downloading %s from %s ...", filename, repo_url)
            with urllib.request.urlopen(repo_url, timeout=30) as response, open(out_path, "wb") as out_file:
                shutil.copyfileobj(response, out_file)
            logging.info("Saved DB: %s", out_path)
        except Exception:
            logging.exception("Error downloading %s from %s", filename, repo_url)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parallel scanner (uses optional good-* DBs).")
    parser.add_argument(
        "--update-db",
        action="store_true",
        help="Download/update DB files from REPO_URLS into ./dbs before scanning (no other flags).",
    )
    args = parser.parse_args()

    logging.info("Starting file scan with Capstone analysis (parallel)...")

    # DB update / load: only the single --update-db flag controls network activity.
    if args.update_db:
        try:
            logging.info("Requested DB update: downloading into ./dbs (force not available).")
            update_databases(force=False, db_dir="./dbs")
            load_good_dbs("./dbs")
        except Exception:
            logging.exception("Failed to update/load good DBs")
    else:
        # Try to load DBs if present; do not attempt network activity.
        try:
            load_good_dbs("./dbs")
        except Exception:
            logging.exception("Failed to load good DBs")

    # Run scan (always uses configured SCAN_FOLDER)
    try:
        results = scan_directory_parallel(SCAN_FOLDER)
    except Exception as exc:
        logging.error("Top-level parallel scan failed: %s", exc)
        results = []

    suspicious_count = 0
    top_offenders = []
    for res in results:
        if res.get("suspicious", False):
            suspicious_count += 1
            top_offenders.append((res.get("suspicious_score", 0), res.get("path")))

    top_offenders.sort(reverse=True)
    logging.info(
        "Scan complete: %d files scanned, %d suspicious files found.",
        len(results),
        suspicious_count,
    )

    if top_offenders:
        logging.info("--- Detailed Analysis of Top Suspicious Files ---")
        for score, path in top_offenders[:20]:
            original_features = next((f for f in results if f.get("path") == path), {})
            notes = []
            if original_features.get("capstone_analysis", {}).get("overall_analysis", {}).get(
                "is_likely_packed"
            ):
                notes.append("Capstone suggests file may be packed")
            if original_features.get("entropy", 0) > 7.5:
                notes.append("High entropy detected")
            if not original_features.get("signature_valid"):
                notes.append(
                    "Invalid or missing signature (Status: %s)"
                    % original_features.get("signature_status", "N/A")
                )

            logging.info("Path: %s (Initial Score: %d)", path, score)
            for note in notes:
                logging.info("  - Triage Note: %s", note)

            logging.info("  - Running on-demand string analysis... (already precomputed)")
            yargen_analysis = original_features.get("yargen_summary", {})
            logging.info("  - String Analysis Result: %s", yargen_analysis.get("status", "N/A"))
            logging.info(
                "    (Found %.1f%% suspicious strings out of %d total.)",
                yargen_analysis.get("yargen_suspicious_percentage", 0.0),
                yargen_analysis.get("total_strings", 0),
            )
    else:
        logging.info("No suspicious files found above the threshold.")
