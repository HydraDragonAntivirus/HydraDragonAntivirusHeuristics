#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suspicious file scanner (YarGen & opcode DB & update-db removed) + PEStudio XML whitelist preserved.

This version:
 - Keeps Phase1 heuristics (entropy, age, signature, capstone packing analysis).
 - Loads PEStudio-style strings XML (whitelist) and injects entries into good_strings_db.
 - Removes YarGen string extraction/scoring, Phase2 ML training/prediction, opcode-related logic/DB flags, and the --update-db downloader.
"""
from __future__ import annotations

import os
import sys
import io
import math
import time
import logging
import argparse
from collections import Counter
from typing import Any, Dict, List, Set, Optional, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

import ctypes
from ctypes import wintypes

# Optional heavy deps (kept where useful)
try:
    import psutil
except Exception:
    psutil = None

try:
    import pefile
except Exception:
    pefile = None

try:
    import capstone
except Exception:
    capstone = None

try:
    import lief
except Exception:
    lief = None

try:
    from tqdm import tqdm
except Exception:
    def tqdm(it, **kwargs): return it

# lxml preferred for robust XML parsing; fallback to ElementTree
try:
    from lxml import etree as lxml_etree
    etree = lxml_etree
except Exception:
    import xml.etree.ElementTree as lxml_etree  # type: ignore
    etree = lxml_etree

# Optional heavy deps (kept where useful)
try:
    import psutil
except Exception:
    psutil = None

try:
    import pefile
except Exception:
    pefile = None

try:
    import capstone
except Exception:
    capstone = None

try:
    import lief
except Exception:
    lief = None

try:
    from tqdm import tqdm
except Exception:
    def tqdm(it, **kwargs): return it

# lxml preferred for robust XML parsing; fallback to ElementTree
try:
    from lxml import etree as lxml_etree
    etree = lxml_etree
except Exception:
    import xml.etree.ElementTree as lxml_etree  # type: ignore
    etree = lxml_etree

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

# DB containers (opcode DB removed)
good_strings_db: Counter = Counter()
good_imphashes_db: Set[str] = set()
good_exports_db: Set[str] = set()

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
# PEStudio whitelist file (user requested location)
# --------------------
PE_STRINGS_FILE = "./3rdparty/strings.xml"

# Known imphashes mapping (example)
KNOWN_IMPHASHES = {
    'a04dd9f5ee88d7774203e0a0cfa1b941': 'PsExec',
    '2b8c9d9ab6fefc247adaf927e83dcea6': 'RAR SFX variant'
}

# pestudio strings global store (populated at startup)
pestudio_strings_global: Dict[str, List[str]] = {}

# --------------------
# Utility functions
# --------------------
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

# --------------------
# PEStudio strings loader & scorer (kept)
# --------------------
def get_abs_path(path: str) -> str:
    """Return an absolute path if possible, otherwise return the input unchanged."""
    try:
        return os.path.abspath(path) if path else path
    except Exception:
        return path


def initialize_pestudio_strings(xml_path: str = PE_STRINGS_FILE) -> Dict[str, List[str]]:
    """
    Parse the PEStudio strings XML and return a dict mapping types to lists of **string texts**.

    This version is permissive: it looks for child tags <string> and <item>, and also
    captures direct node text. It normalizes (strips, lowercases) and deduplicates the results.
    It also builds a fast lookup map `pestudio_marker` for O(1) matching.
    """
    keys = ["strings", "av", "folder", "os", "reg", "guid", "ssdl", "ext", "agent", "oid", "priv"]
    pestudio: Dict[str, List[str]] = {k: [] for k in keys}

    try:
        if not xml_path or not os.path.exists(xml_path):
            logging.info("PEStudio strings XML not found: %s", xml_path)
            return pestudio

        tree = etree.parse(get_abs_path(xml_path))
        root = tree.getroot()

        for k in keys:
            nodes = root.findall('.//' + k)
            for node in nodes:
                # prefer children named 'string' or 'item'
                for child_tag in ("string", "item"):
                    for child in node.findall('.//' + child_tag):
                        if child is None or child.text is None:
                            continue
                        s = child.text.strip()
                        if s:
                            pestudio[k].append(s)
                # fallback to node text
                if (node.text is not None) and node.text.strip():
                    pestudio[k].append(node.text.strip())

        # normalize: strip, dedupe, preserve case variants (store lower for marker)
        for k in keys:
            seen = set()
            cleaned = []
            for it in pestudio[k]:
                if not it:
                    continue
                norm = it.strip()
                if not norm:
                    continue
                if norm in seen:
                    continue
                seen.add(norm)
                cleaned.append(norm)
            pestudio[k] = cleaned

        # build a quick marker dict for O(1) lookups (lowercased keys)
        global pestudio_marker
        pestudio_marker = {}
        for typ, lst in pestudio.items():
            for s in lst:
                if s:
                    pestudio_marker[s.strip().lower()] = typ

        logging.info("Loaded pestudio strings from %s: %s", xml_path, {k: len(v) for k, v in pestudio.items()})
        return pestudio

    except Exception as e:
        logging.exception("Failed to initialize pestudio strings from %s: %s", xml_path, e)
        return pestudio


def get_pestudio_score(string: str) -> Tuple[int, str]:
    """
    Efficient lookup using the pre-built `pestudio_marker` map.

    Returns (score:int, matched_type:str). Score 5 for exact full match found in pestudio lists
    (excluding the 'ext' type which is ignored).
    """
    if not string:
        return 0, ""
    # build marker on first use if missing
    global pestudio_marker, pestudio_strings_global
    try:
        if 'pestudio_marker' not in globals() or not pestudio_marker:
            # ensure pestudio_strings_global is initialized
            if not pestudio_strings_global:
                pestudio_strings_global = initialize_pestudio_strings(PE_STRINGS_FILE)
            # initialize marker from global store
            pestudio_marker = {}
            for typ, lst in pestudio_strings_global.items():
                for s in lst:
                    if s:
                        pestudio_marker[s.strip().lower()] = typ
    except Exception:
        pestudio_marker = {}

    key = string.strip().lower()
    typ = pestudio_marker.get(key)
    if not typ:
        return 0, ""
    if typ == 'ext':
        return 0, ""
    return 5, typ
    s_lower = string.strip().lower()
    for typ, lst in pestudio_strings.items():
        if not lst:
            continue
        if typ == "ext":
            continue  # skip extensions as per original code
        for item in lst:
            if not item:
                continue
            if item.strip().lower() == s_lower:
                return 5, typ
    return 0, ""

# --------------------
# DB Management (keeps local db loading from ./dbs, downloader removed)
# --------------------
# --------------------
# PE/Capstone utilities (kept)
# --------------------
def get_pe_info(file_bytes: bytes) -> Tuple[str, List[str]]:
    imphash, exports = "", []
    if not file_bytes or file_bytes[:2] != b'MZ':
        return imphash, exports
    if lief:
        try:
            binary = lief.parse(io.BytesIO(file_bytes))
            if isinstance(binary, lief.PE.Binary):
                try:
                    imphash = lief.PE.get_imphash(binary, lief.PE.PE.IMPHASH_MODE.PEFILE)
                except Exception:
                    imphash = ""
                if binary.has_exports:
                    for e in binary.exported_functions:
                        if e.name:
                            exports.append(e.name)
        except Exception:
            pass
    else:
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


def analyze_with_capstone_pe(pe_obj) -> Dict[str, Any]:
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

        analysis["overall_analysis"]["add_count"] = total_add
        analysis["overall_analysis"]["mov_count"] = total_mov
        analysis["overall_analysis"]["total_instructions"] = total_instructions
        analysis["overall_analysis"]["is_likely_packed"] = (total_add > total_mov) if total_instructions > 0 else False

    except Exception as e:
        analysis["error"] = str(e)

    return analysis

# --------------------
# WinVerifyTrust signature checking (kept)
# --------------------
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
        ("dwStateAction", ctypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", ctypes.DWORD),
        ("dwUIContext", ctypes.DWORD),
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
# Runtime helpers
# --------------------
def is_running_pe(path: str) -> bool:
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

def is_in_suspicious_location_pe(path: str) -> bool:
    path_norm = os.path.normcase(path)
    for d in SUSPICIOUS_DIRS + SYSTEM_DIRS + STARTUP_DIRS:
        if d and os.path.normcase(d) in path_norm:
            return True
    return False

# --------------------
# Single-file analysis (Phase1 only)
# --------------------
def analyze_single_file(path: str) -> dict:
    """
    Phase1 heuristics + PE-specific checks. Returns features dict including `pe_checks`.
    Each entry in `pe_checks` is a tuple: (message, verdict) where verdict is one of
    'Clean', 'Suspicious', or 'Unknown'.
    """
    features: Dict[str, Any] = {
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
        # phase2 placeholders (removed/unused but keep for compatibility)
        'phase2_summary': None,
        'phase2_percentage': 0.0,
        # new: detailed checks
        'pe_checks': []
    }

    # verdict defaults following your table
    verdict_map = {
        "Optional Header LoaderFlags field is valued illegal": "Clean",
        "Non-ascii or empty section names detected": "Clean",
        "Illegal size of optional Header": "Clean",
        "Packer detection on signature database": "Unknown",
        "Based on the sections entropy check! file is possibly packed": "Clean",
        "Timestamp value suspicious": "Clean",
        "Header Checksum is zero!": "Suspicious",
        "Entry point is outside the 1st(.code) section! Binary is possibly packed": "Clean",
        "Optional Header NumberOfRvaAndSizes field is valued illegal": "Clean",
        "Anti-vm present": "Clean",
        "The Size Of Raw data is valued illegal! Binary might crash your disassembler/debugger": "Suspicious",
        "TLS callback functions array detected": "Clean"
    }

    try:
        stats = os.stat(path)
        features['size'] = stats.st_size
        features['age_days'] = (time.time() - stats.st_ctime) / (24 * 3600)
        features['entropy'] = calculate_entropy(path)

        # read file bytes once (used for imphash/signature checks)
        file_bytes = b''
        try:
            with open(path, 'rb') as fh:
                file_bytes = fh.read()
        except Exception:
            file_bytes = b''

        pe = None
        try:
            if pefile:
                pe = pefile.PE(path)
                features['is_executable'] = True
                features['has_version_info'] = hasattr(pe, 'VS_FIXEDFILEINFO') and getattr(pe, 'VS_FIXEDFILEINFO') is not None

                # capstone analysis (best-effort)
                try:
                    cap_analysis = analyze_with_capstone_pe(pe)
                    if cap_analysis is None:
                        cap_analysis = {
                            "overall_analysis": {
                                "is_likely_packed": False,
                                "add_count": 0,
                                "mov_count": 0,
                                "total_instructions": 0
                            },
                            "sections": {},
                            "error": "Capstone analysis returned None"
                        }
                    features['capstone_analysis'] = cap_analysis
                except Exception as e:
                    logging.debug("Capstone analysis failed for %s: %s", path, e)
                    features['capstone_analysis'] = {
                        "overall_analysis": {
                            "is_likely_packed": False,
                            "add_count": 0,
                            "mov_count": 0,
                            "total_instructions": 0
                        },
                        "sections": {},
                        "error": f"Capstone analysis exception: {e}"
                    }

                # --- PE-specific checks ---
                pe_checks: List[Tuple[str, str]] = []

                # Optional Header LoaderFlags non-zero
                try:
                    lf = getattr(pe.OPTIONAL_HEADER, 'LoaderFlags', None)
                    if lf is not None and int(lf) != 0:
                        msg = "Optional Header LoaderFlags field is valued illegal"
                        pe_checks.append((msg, verdict_map.get(msg, 'Clean')))
                except Exception:
                    pass

                # Non-ascii or empty section names
                try:
                    found_bad_name = False
                    for sec in pe.sections:
                        try:
                            name = sec.Name.decode(errors='ignore').strip(b'\x00')
                        except Exception:
                            name = ""
                        if not name or any(ord(c) < 32 or ord(c) > 126 for c in name):
                            found_bad_name = True
                            break
                    if found_bad_name:
                        msg = "Non-ascii or empty section names detected"
                        pe_checks.append((msg, verdict_map.get(msg, 'Clean')))
                except Exception:
                    pass

                # Illegal SizeOfOptionalHeader
                try:
                    soh = getattr(getattr(pe, 'FILE_HEADER', None), 'SizeOfOptionalHeader', None)
                    if soh is not None and (soh < 0x60 or soh > 0x1000):
                        msg = "Illegal size of optional Header"
                        pe_checks.append((msg, verdict_map.get(msg, 'Clean')))
                except Exception:
                    pass

                # Sections entropy -> possibly packed
                try:
                    for sec in pe.sections:
                        data = sec.get_data() or b''
                        if not data:
                            continue
                        freq = [0] * 256
                        total = 0
                        for b in data:
                            total += 1
                            freq[b] += 1
                        ent = 0.0
                        if total > 0:
                            for f in freq:
                                if f > 0:
                                    p = f / total
                                    ent -= p * math.log2(p)
                        if ent > 7.5:
                            msg = "Based on the sections entropy check! file is possibly packed"
                            pe_checks.append((msg, verdict_map.get(msg, 'Clean')))
                            break
                except Exception:
                    pass

                # Timestamp suspicious
                try:
                    ts = getattr(getattr(pe, 'FILE_HEADER', None), 'TimeDateStamp', 0)
                    if ts == 0 or ts > int(time.time()) + 365*24*3600:
                        msg = "Timestamp value suspicious"
                        pe_checks.append((msg, verdict_map.get(msg, 'Clean')))
                except Exception:
                    pass

                # Header Checksum zero
                try:
                    chksum = getattr(pe.OPTIONAL_HEADER, 'CheckSum', None)
                    if chksum is not None and int(chksum) == 0:
                        msg = "Header Checksum is zero!"
                        pe_checks.append((msg, verdict_map.get(msg, 'Suspicious')))
                except Exception:
                    pass

                # Entry point outside first .text/.code section
                try:
                    ep = int(getattr(pe, 'OPTIONAL_HEADER').AddressOfEntryPoint)
                    first_code_section = None
                    for s in pe.sections:
                        name = s.Name.decode(errors='ignore').strip(b'\x00').lower()
                        if name in ('.text', '.code'):
                            first_code_section = s
                            break
                    if first_code_section is not None:
                        va = int(first_code_section.VirtualAddress)
                        size = int(first_code_section.Misc_VirtualSize)
                        if not (va <= ep < va + size):
                            msg = "Entry point is outside the 1st(.code) section! Binary is possibly packed"
                            pe_checks.append((msg, verdict_map.get(msg, 'Clean')))
                except Exception:
                    pass

                # NumberOfRvaAndSizes abnormal
                try:
                    nrva = getattr(pe.OPTIONAL_HEADER, 'NumberOfRvaAndSizes', None)
                    if nrva is not None and (nrva < 10 or nrva > 64):
                        msg = "Optional Header NumberOfRvaAndSizes field is valued illegal"
                        pe_checks.append((msg, verdict_map.get(msg, 'Clean')))
                except Exception:
                    pass

                # Simple anti-VM detection via import names
                try:
                    imports = []
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for imp in getattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                            if imp.dll:
                                imports.append(imp.dll.decode(errors='ignore').lower())
                    anti_vm_found = any(x for x in ('vbox', 'vmware', 'vmwareuser', 'xen') if any(x in i for i in imports))
                    if anti_vm_found:
                        msg = "Anti-vm present"
                        pe_checks.append((msg, verdict_map.get(msg, 'Clean')))
                except Exception:
                    pass

                # SizeOfRawData irregularities
                try:
                    for sec in pe.sections:
                        if hasattr(sec, 'SizeOfRawData') and hasattr(sec, 'Misc_VirtualSize'):
                            if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0:
                                msg = "The Size Of Raw data is valued illegal! Binary might crash your disassembler/debugger"
                                pe_checks.append((msg, verdict_map.get(msg, 'Suspicious')))
                                break
                except Exception:
                    pass

                # TLS callbacks presence -> now marked Clean per your requested table
                try:
                    if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and getattr(pe, 'DIRECTORY_ENTRY_TLS') is not None:
                        msg = "TLS callback functions array detected"
                        pe_checks.append((msg, verdict_map.get(msg, 'Clean')))
                except Exception:
                    pass

                # Packer detection via imphash/signature database
                try:
                    imphash, exports = get_pe_info(file_bytes)
                    if imphash:
                        name = KNOWN_IMPHASHES.get(imphash.lower())
                        if name:
                            msg = "Packer detection on signature database"
                            pe_checks.append((f"{msg}: {name}", verdict_map.get(msg, 'Unknown')))
                except Exception:
                    pass

                features['pe_checks'] = pe_checks

        except Exception as e:
            logging.debug("PE parsing failed for %s: %s", path, e)
        finally:
            if pe:
                try:
                    pe.close()
                except Exception:
                    pass

        # Ensure capstone_analysis is always present
        if features['capstone_analysis'] is None:
            features['capstone_analysis'] = {
                "overall_analysis": {
                    "is_likely_packed": False,
                    "add_count": 0,
                    "mov_count": 0,
                    "total_instructions": 0
                },
                "sections": {},
                "error": "No PE file or capstone not available"
            }

        try:
            sig = check_valid_signature(path)
            features['signature_valid'] = sig.get('is_valid', False)
            features['signature_status'] = sig.get('status', "N/A")
        except Exception:
            pass

        # --------------------
        # Phase 1 scoring
        # --------------------
        phase1 = 0
        cap = features['capstone_analysis'].get('overall_analysis', {})

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

        features['phase1_score'] = phase1
        features['suspicious_score'] = phase1
        features['suspicious'] = phase1 >= SUSPICIOUS_THRESHOLD

        if features['suspicious']:
            logging.info(f"[Phase 1] Suspicious detected: {path} | Score: {phase1}")

    except Exception as e:
        logging.error(f"Failed to analyze {path}: {e}")
        features['error'] = str(e)

    return features

# --------------------
# Directory scanning (parallel)
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
# CLI / main (update-db option removed)
# --------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Suspicious file scanner (YarGen/opcode/update-db removed)")
    parser.add_argument("-m", "--malware-path", dest="scan_path", default=SCAN_FOLDER, help="Directory to scan")
    parser.add_argument("-t", "--threshold", type=int, default=SUSPICIOUS_THRESHOLD, help="Suspicion threshold")
    parser.add_argument('--whitelist-xml', dest='whitelist_xml', default=PE_STRINGS_FILE, help='Path to pestudio strings.xml (whitelist)')

    args = parser.parse_args()

    SUSPICIOUS_THRESHOLD = int(args.threshold)
    SCAN_FOLDER = args.scan_path

    print("--- Suspicious file scanner (YarGen/opcode/update-db removed) ---")

    # Load DBs (local ./dbs only)

    # Load pestudio whitelist XML (no local good_* DBs used)
    try:
        pestudio_strings_global = initialize_pestudio_strings(args.whitelist_xml)
    except Exception as e:
        logging.warning("Failed to load pestudio whitelist: %s", e)

    print(f"Starting scan: {SCAN_FOLDER}")
    start = time.time()
    results = scan_directory_parallel(SCAN_FOLDER)
    dur = time.time() - start

    suspicious = [r for r in results if r and r.get("suspicious")]
    print("\n--- Scan Summary ---")
    print(f"Completed in {dur:.2f}s. Files scanned: {len(results)} Suspicious: {len(suspicious)}")
    if suspicious:
        suspicious.sort(key=lambda x: x.get("suspicious_score", 0), reverse=True)
        print("\nTop suspicious files:")
        for r in suspicious[:20]:
            print(f"{r['path']}\n  Phase1 Score: {r.get('phase1_score', 0)}  Sig: {r.get('signature_status','N/A')}")
    print("Done. See log for details.")
