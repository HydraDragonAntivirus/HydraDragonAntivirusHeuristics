# scanner_capstone_parallel.py
# Parallelized version of scanner_capstone_only.py using ProcessPoolExecutor

import os
import math
import pefile
import hashlib
import time
import ctypes
import logging
from ctypes import wintypes
import psutil
import capstone
from tqdm import tqdm
from typing import Dict, Any, Set, List, Tuple, Optional
from concurrent.futures import ProcessPoolExecutor
import functools

# -----------------------
# Configuration & Constants
# -----------------------
SCAN_FOLDER = "datamaliciousorder"                # folder to scan by default
SUSPICIOUS_THRESHOLD = 11            # scoring threshold (adjust)

# -----------------------
# Logging
# -----------------------
logging.basicConfig(
    filename="scanner.log",
    filemode="a",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# -----------------------
# WinVerifyTrust / Authenticode constants
# -----------------------
crypt32 = ctypes.windll.crypt32

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
        ("dwUnionChoice", wintypes.DWORD),
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

_wintrust = ctypes.windll.wintrust

TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0008
TRUST_E_PROVIDER_UNKNOWN     = 0x800B0001
CERT_E_UNTRUSTEDROOT         = 0x800B0109
NO_SIGNATURE_CODES = {TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN}

# -----------------------
# Directories & lookup names
# -----------------------
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

LOOKUP_FILENAMES = {
    'system_names': ['system_filenames.txt'],
    'av_processes': ['antivirus_process_list.txt']
}

LOOKUP_DIR = "known_extensions"  # folder containing the lookup files

# -----------------------
# Helper functions for lookups
# -----------------------
def read_lines_set(path: str) -> Set[str]:
    s = set()
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                line = line.strip('"').strip("'").lower()
                s.add(line)
    except Exception as e:
        logging.error(f"Failed reading lookup file {path}: {e}")
    return s


def load_all_lookups():
    system_names_set = set()
    av_processes_set = set()

    for filename in LOOKUP_FILENAMES['system_names']:
        path = os.path.join(LOOKUP_DIR, filename)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                system_names_set.update(line.strip() for line in f if line.strip())

    for filename in LOOKUP_FILENAMES['av_processes']:
        path = os.path.join(LOOKUP_DIR, filename)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                av_processes_set.update(line.strip() for line in f if line.strip())

    return system_names_set, av_processes_set

# -----------------------
# Utility: entropy calculation
# -----------------------
def calculate_entropy(path: str) -> float:
    """Calculate Shannon entropy of file."""
    freq = [0] * 256
    total = 0
    try:
        with open(path, 'rb') as fh:
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
        logging.error(f"Failed calculating entropy for {path}: {e}")
        return 0.0

# -----------------------
# Capstone-only analysis
# -----------------------
def analyze_with_capstone(pe) -> Dict[str, Any]:
    analysis = {
        'overall_analysis': {
            'total_instructions': 0,
            'add_count': 0,
            'mov_count': 0,
            'is_likely_packed': None
        },
        'sections': {},
        'error': None
    }

    try:
        # Determine architecture for Capstone
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            analysis['error'] = "Unsupported architecture."
            return analysis

        total_add_count = 0
        total_mov_count = 0
        grand_total_instructions = 0

        # Disassemble each section individually
        for section in pe.sections:
            section_name = section.Name.decode(errors='ignore').strip('\x00')
            code = section.get_data()
            base_address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

            instruction_counts = {}
            total_instructions_in_section = 0

            if not code:
                analysis['sections'][section_name] = {
                    'instruction_counts': {},
                    'total_instructions': 0,
                    'add_count': 0,
                    'mov_count': 0,
                    'is_likely_packed': False
                }
                continue

            instructions = md.disasm(code, base_address)

            for i in instructions:
                mnemonic = i.mnemonic
                instruction_counts[mnemonic] = instruction_counts.get(mnemonic, 0) + 1
                total_instructions_in_section += 1

            add_count = instruction_counts.get('add', 0)
            mov_count = instruction_counts.get('mov', 0)

            # Aggregate counts for overall file analysis
            total_add_count += add_count
            total_mov_count += mov_count
            grand_total_instructions += total_instructions_in_section

            # Per-section packing analysis
            analysis['sections'][section_name] = {
                'instruction_counts': instruction_counts,
                'total_instructions': total_instructions_in_section,
                'add_count': add_count,
                'mov_count': mov_count,
                'is_likely_packed': add_count > mov_count if total_instructions_in_section > 0 else False
            }

        # Populate the overall, file-wide analysis
        analysis['overall_analysis']['total_instructions'] = grand_total_instructions
        analysis['overall_analysis']['add_count'] = total_add_count
        analysis['overall_analysis']['mov_count'] = total_mov_count
        analysis['overall_analysis']['is_likely_packed'] = total_add_count > total_mov_count if grand_total_instructions > 0 else False

    except Exception as e:
        logging.error(f"Capstone disassembly failed: {e}")
        analysis['error'] = str(e)

    return analysis

# -----------------------
# Authenticode wrapper
# -----------------------
def _build_wtd_for(file_path: str) -> WINTRUST_DATA:
    file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), file_path, None, None)
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
    return _wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd))

def check_valid_signature(file_path: str) -> dict:
    """
    Returns {"is_valid": bool, "status": str}.
    - Valid -> {"is_valid": True, "status": "Valid"}
    - No signature -> {"is_valid": False, "status": "No signature"}
    - Untrusted root -> {"is_valid": False, "status": "Untrusted root"}  # NOT flagged as generic Invalid
    - Fully invalid (bad digest / cert sig failure) -> logged warning, status explains reason
    - Other failures -> logged warning, returned as 'Invalid signature (HRESULT=0x...)'
    """
    # HRESULTs that indicate a present-but-broken signature
    TRUST_E_BAD_DIGEST = 0x80096010      # digital signature did not verify (bad digest)
    TRUST_E_CERT_SIGNATURE = 0x80096004  # signature of the certificate cannot be verified

    try:
        result = verify_authenticode_signature(file_path)
        hresult = result & 0xFFFFFFFF

        if hresult == 0:
            return {"is_valid": True, "status": "Valid"}

        if hresult in NO_SIGNATURE_CODES:
            return {"is_valid": False, "status": "No signature"}

        # Explicit: do NOT treat untrusted root as generic "Invalid signature"
        if hresult == CERT_E_UNTRUSTEDROOT:
            return {"is_valid": False, "status": "Untrusted root"}

        # Digest mismatch -> fully invalid (likely tampered)
        if hresult == TRUST_E_BAD_DIGEST:
            status = f"Fully invalid (bad digest / signature mismatch) (HRESULT=0x{hresult:08X})"
            logging.warning(f"[Signature] {file_path}: {status}")
            return {"is_valid": False, "status": status}

        # Certificate signature verification failed -> fully invalid
        if hresult == TRUST_E_CERT_SIGNATURE:
            status = f"Fully invalid (certificate signature verification failed) (HRESULT=0x{hresult:08X})"
            logging.warning(f"[Signature] {file_path}: {status}")
            return {"is_valid": False, "status": status}

        # Fallback for other non-trivial signature failures
        status = f"Invalid signature (HRESULT=0x{hresult:08X})"
        logging.warning(f"[Signature] {file_path}: {status}")
        return {"is_valid": False, "status": status}

    except Exception as ex:
        logging.error(f"[Signature] check failed for {file_path}: {ex}")
        return {"is_valid": False, "status": str(ex)}

# -----------------------
# Runtime / location helpers
# -----------------------
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

# -----------------------
# Single file analysis
# -----------------------
def analyze_single_file(path: str, system_names: Set[str], av_processes: Set[str]) -> Dict[str, Any]:
    """Analyze a single file with Capstone disassembly and basic checks."""
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
        'extension': '',
        'suspicious_score': 0,
        'suspicious': False
    }

    try:
        # Basic file info
        stats = os.stat(path)
        features['size'] = stats.st_size
        features['age_days'] = (time.time() - stats.st_ctime) / (24*3600)
        features['entropy'] = calculate_entropy(path)
        
        filename = os.path.basename(path)
        filename_lc = filename.lower()
        ext = os.path.splitext(filename_lc)[1].lstrip('.')
        features['extension'] = ext

        # Check if it's executable
        exe_like_exts = ('.exe', '.dll', '.sys', '.ocx', '.wll', '.scr', '.com', '.drv')
        if filename.endswith(exe_like_exts):
            features['is_executable'] = True

        # PE analysis with Capstone
        pe = None
        try:
            pe = pefile.PE(path)
            features['is_executable'] = True
            features['has_version_info'] = hasattr(pe, 'VS_FIXEDFILEINFO') and getattr(pe, 'VS_FIXEDFILEINFO') is not None
            
            # Capstone disassembly analysis
            features['capstone_analysis'] = analyze_with_capstone(pe)
            
        except Exception as e:
            logging.debug(f"PE analysis failed for {path}: {e}")
        finally:
            if pe:
                try:
                    pe.close()
                except Exception:
                    pass

        # Signature check
        if features['is_executable']:
            try:
                sig = check_valid_signature(path)
                features['signature_valid'] = sig.get('is_valid', False)
                features['signature_status'] = sig.get('status', "N/A")
            except Exception as e:
                logging.debug(f"Signature check failed for {path}: {e}")

        # Runtime checks
        if features['is_executable']:
            features['is_running'] = is_running_pe(path)
            features['in_suspicious_location'] = is_in_suspicious_location_pe(path)

        # Calculate suspicious score
        score = 0

        # Capstone packing detection
        if (features.get('capstone_analysis') and 
            features['capstone_analysis'].get('overall_analysis', {}).get('is_likely_packed')):
            score += 3

        # Entropy
        if features.get('entropy', 0) > 7.5:
            if features.get('signature_valid'):
                score += 2
            else:
                score += 5

        # Age <1 day
        if features.get('age_days', 0) < 1:
            score += 2

        # Temp/cache path
        if 'temp' in path.lower() or 'cache' in path.lower():
            score += 2

        # Version info
        if features.get('is_executable'):
            if not features.get('has_version_info') and not features.get('signature_valid'):
                score += 1

        # Signature invalid/untrusted
        if features.get('is_executable') and not features.get('signature_valid'):
            if features.get('signature_status') == "Untrusted root":
                score += 4
            else:
                score += 2

        # Reduce for valid signature
        if features.get('signature_valid'):
            score = max(score - 3, 0)

        # Suspicious location
        if features.get('in_suspicious_location'):
            score += 2

        # Running
        if features.get('is_running'):
            score += 3

        # Impersonation via lookups
        base_name = filename_lc
        if base_name in system_names or base_name in av_processes:
            score += 4

        # Extension: only penalize if missing extension
        if ext == '':
            score += 2

        # .wll handling
        if ext == 'wll':
            in_startup = any(os.path.normcase(d) in os.path.normcase(path) for d in STARTUP_DIRS if d)
            in_system = any(os.path.normcase(d) in os.path.normcase(path) for d in SYSTEM_DIRS if d)
            if in_startup or in_system:
                score += 5

        features['suspicious_score'] = score
        features['suspicious'] = score >= SUSPICIOUS_THRESHOLD

    except Exception as e:
        logging.error(f"Failed to analyze {path}: {e}")
        features['error'] = str(e)

    return features

# -----------------------
# Directory scanning (sequential fallback)
# -----------------------
def scan_directory_sequential(folder, system_names_set, av_processes_set):
    print(f"Scanning directory (sequential): {folder}")
    results = []
    total_files = 0
    suspicious_count = 0

    for root, _, files in os.walk(folder):
        for f in tqdm(files, desc=f"Scanning {os.path.basename(root)}", unit="file", leave=False):
            path = os.path.join(root, f)
            total_files += 1
            try:
                features = analyze_single_file(path, system_names_set, av_processes_set)
                results.append((path, features))

                score = features.get('suspicious_score', 0)
                if features.get('suspicious', False):
                    suspicious_count += 1
                    logging.warning(f"SUSPICIOUS DETECTED: {path} (Score: {score})")
                elif score > SUSPICIOUS_THRESHOLD * 0.7:
                    logging.info(f"High score file: {path} (Score: {score})")
            except Exception as e:
                logging.error(f"Failed to analyze {path}: {e}")
                results.append((path, {'error': str(e), 'suspicious_score': 0, 'suspicious': False}))

    logging.info(f"Scan complete: {total_files} files scanned, {suspicious_count} suspicious")
    return results

# -----------------------
# Directory scanning (parallel)
# -----------------------
def scan_directory_parallel(folder, system_names_set, av_processes_set, max_workers: Optional[int] = None):
    """Scan directory and analyze files in parallel using ProcessPoolExecutor."""
    print(f"Scanning directory (parallel): {folder}")

    # Build file list first (so we can show a progress bar)
    file_paths: List[str] = []
    for root, _, files in os.walk(folder):
        for f in files:
            file_paths.append(os.path.join(root, f))

    total_files = len(file_paths)
    if total_files == 0:
        print("No files found to scan.")
        return []

    results: List[Tuple[str, Dict[str, Any]]] = []
    suspicious_count = 0

    # Worker function is analyze_single_file(path, system_names, av_processes)
    worker = functools.partial(analyze_single_file, system_names=system_names_set, av_processes=av_processes_set)

    try:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            # executor.map will preserve order; wrap the iterator with tqdm to show progress
            results_iter = executor.map(worker, file_paths)
            for idx, features in enumerate(tqdm(results_iter, total=total_files, desc="Processing files", unit="file")):
                path = file_paths[idx]
                results.append((path, features))

                score = features.get('suspicious_score', 0)
                if features.get('suspicious', False):
                    suspicious_count += 1
                    logging.warning(f"SUSPICIOUS DETECTED: {path} (Score: {score})")
                elif score > SUSPICIOUS_THRESHOLD * 0.7:
                    logging.info(f"High score file: {path} (Score: {score})")

    except Exception as e:
        logging.error(f"Parallel scan failed: {e}")
        print("Parallel scan failed, falling back to sequential scan. See scanner.log for details.")
        return scan_directory_sequential(folder, system_names_set, av_processes_set)

    logging.info(f"Scan complete: {total_files} files scanned, {suspicious_count} suspicious")
    return results

# -----------------------
# Main execution
# -----------------------
if __name__ == "__main__":
    # Important: keep heavy/OS-specific initialization guarded by this main-check so
    # worker processes (on Windows) don't re-run top-level scan logic on import.
    system_names_set, av_processes_set = load_all_lookups()
    print(f"Loaded {len(system_names_set)} system names, {len(av_processes_set)} AV process names")
    print("Starting file scan with Capstone analysis (parallel)...")

    # Try to use a reasonable default for worker count if not provided
    default_workers = min(32, (os.cpu_count() or 1) * 2)
    try:
        results = scan_directory_parallel(SCAN_FOLDER, system_names_set, av_processes_set, max_workers=default_workers)
    except Exception as e:
        logging.error(f"Top-level parallel scan failed: {e}")
        results = scan_directory_sequential(SCAN_FOLDER, system_names_set, av_processes_set)

    suspicious_count = 0
    top_offenders = []

    for path, res in results:
        score = res.get('suspicious_score', 0)
        if res.get('suspicious', False):
            suspicious_count += 1
            top_offenders.append((score, path))

    top_offenders.sort(reverse=True)
    print(f"Scan complete: {len(results)} files scanned, {suspicious_count} suspicious.")
    
    if top_offenders:
        print("Top suspicious files (score, path):")
        for score, path in top_offenders[:10]:
            capstone_packed = ""
            for _, features in results:
                if features.get('path') == path:
                    capstone_analysis = features.get('capstone_analysis')
                    if capstone_analysis and capstone_analysis.get('overall_analysis', {}).get('is_likely_packed'):
                        capstone_packed = " [PACKED]"
                    break
            print(f"  {score:3d}  {path}{capstone_packed}")
    else:
        print("No suspicious files found above threshold.")
