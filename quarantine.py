#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Handles high-risk quarantine operations including critical process termination
and secure file moving. All functions in this module should be used with
extreme caution.
"""

import os
import ctypes
import psutil
import hydra_logger
import time

# --- Globals & WinAPI Definitions ---
QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")

# Define necessary Windows types and constants
PVOID = ctypes.c_void_p
HANDLE = PVOID
BOOL = ctypes.c_bool
DWORD = ctypes.c_ulong
ULONG_PTR = ctypes.POINTER(DWORD)
NTSTATUS = ctypes.c_long

# Process access rights
PROCESS_ALL_ACCESS = 0x1F0FFF
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

# --- WinAPI Function Prototypes via ctypes ---
try:
    ntdll = ctypes.WinDLL('ntdll.dll')
    advapi32 = ctypes.WinDLL('advapi32.dll')
    kernel32 = ctypes.WinDLL('kernel32.dll')

    # RtlSetProcessIsCritical (undocumented, use with extreme care)
    # NTSTATUS RtlSetProcessIsCritical(BOOLEAN NewValue, PBOOLEAN OldValue, BOOLEAN IsWinlogon);
    RtlSetProcessIsCritical = ntdll.RtlSetProcessIsCritical
    RtlSetProcessIsCritical.argtypes = [BOOL, PVOID, BOOL]
    RtlSetProcessIsCritical.restype = NTSTATUS

    # Functions for enabling SeDebugPrivilege
    OpenProcessToken = advapi32.OpenProcessToken
    LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
    AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
except (OSError, AttributeError) as e:
    hydra_logger.logger.critical("Failed to load necessary WinAPIs: {}. Quarantine functions will fail.".format(e))
    ntdll = advapi32 = kernel32 = None

# C structures for token manipulation
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", DWORD), ("HighPart", ctypes.c_long)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

def set_process_privilege(privilege_name, enable=True):
    """Enables or disables a specific privilege (e.g., 'SeDebugPrivilege') for the current process."""
    if not advapi32: return False
    
    hToken = HANDLE()
    privilege_id = LUID()
    
    # Get current process token
    if not OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
        hydra_logger.logger.error("OpenProcessToken failed: {}".format(ctypes.get_last_error()))
        return False

    # Get the LUID for the privilege
    if not LookupPrivilegeValueW(None, privilege_name, ctypes.byref(privilege_id)):
        hydra_logger.logger.error("LookupPrivilegeValueW failed: {}".format(ctypes.get_last_error()))
        kernel32.CloseHandle(hToken)
        return False
    
    # Prepare the TOKEN_PRIVILEGES structure
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = privilege_id
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED if enable else 0
    
    # Adjust the token privileges
    if not AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None):
        hydra_logger.logger.error("AdjustTokenPrivileges failed: {}".format(ctypes.get_last_error()))
        kernel32.CloseHandle(hToken)
        return False

    kernel32.CloseHandle(hToken)
    return True

def make_process_critical(pid):
    """
    Sets a process as critical. If this process is terminated by any means
    other than a clean shutdown, the system will crash (BSOD).
    THIS IS EXTREMELY DANGEROUS.
    """
    if not ntdll or not kernel32:
        hydra_logger.logger.error("ntdll or kernel32 not loaded. Cannot make process critical.")
        return False

    hydra_logger.logger.warning("Attempting to escalate privileges to set PID {} as critical.".format(pid))
    if not set_process_privilege('SeDebugPrivilege'):
        hydra_logger.logger.error("Failed to acquire SeDebugPrivilege. Aborting critical process operation.")
        return False

    try:
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not hProcess:
            hydra_logger.logger.error("OpenProcess failed for PID {}: {}".format(pid, ctypes.get_last_error()))
            return False

        is_critical_status = BOOL(True)
        # Call the undocumented NT function.
        # Params: NewValue=True, OldValue=None, IsWinlogon=False
        status = RtlSetProcessIsCritical(is_critical_status, None, False)

        kernel32.CloseHandle(hProcess)

        if status == 0: # NT_SUCCESS
            hydra_logger.logger.info("Successfully set PID {} as a critical process.".format(pid))
            return True
        else:
            hydra_logger.logger.error("RtlSetProcessIsCritical failed for PID {} with NTSTATUS: {}".format(pid, status))
            return False
    except Exception as e:
        hydra_logger.logger.error("Exception while making process critical: {}".format(e), exc_info=True)
        return False

def terminate_process_by_path(file_path):
    """
    Finds a running process by its executable path, attempts to make it critical,
    and then forcefully terminates it.
    """
    target_proc = None
    try:
        norm_path = os.path.normcase(file_path)
        for proc in psutil.process_iter(['exe', 'pid', 'name']):
            try:
                if proc.info['exe'] and os.path.normcase(proc.info['exe']) == norm_path:
                    target_proc = proc
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
                continue
        
        if not target_proc:
            return True, "Process was not running."

        pid = target_proc.pid
        hydra_logger.logger.info("Found process {} (PID: {}) for path {}.".format(target_proc.name(), pid, file_path))
        
        # The high-risk operation
        if not make_process_critical(pid):
            hydra_logger.logger.warning("Could not set PID {} as critical. Proceeding with normal termination.".format(pid))

        hydra_logger.logger.critical("Terminating critical process {}.".format(pid))
        target_proc.kill()
        
        try:
            target_proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            return False, "Process {} did not terminate in time.".format(pid)
            
        return True, "Process {} terminated successfully.".format(pid)

    except Exception as e:
        hydra_logger.logger.error("Failed to terminate process for {}: {}".format(file_path, e), exc_info=True)
        return False, "Error terminating process: {}".format(e)

def quarantine_file(file_path):
    """
    Moves a file to the quarantine directory, renaming it to prevent execution.
    """
    if not os.path.exists(file_path):
        return False, "File no longer exists."
        
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        
        base_name = os.path.basename(file_path)
        timestamp = int(time.time())
        quarantine_name = "{}_{}.quarantined".format(timestamp, base_name)
        destination = os.path.join(QUARANTINE_DIR, quarantine_name)
        
        os.rename(file_path, destination)
        
        msg = "File successfully moved to: {}".format(destination)
        hydra_logger.logger.info(msg)
        return True, msg

    except Exception as e:
        hydra_logger.logger.error("Failed to move {} to quarantine: {}".format(file_path, e), exc_info=True)
        return False, "Error moving file: {}".format(e)

def initiate_quarantine(file_path):
    """
    Coordinates the full quarantine procedure: terminate process, then move file.
    """
    hydra_logger.logger.warning("--- INITIATING QUARANTINE for {} ---".format(file_path))
    
    # 1. Terminate the running process
    term_success, term_msg = terminate_process_by_path(file_path)
    
    if not term_success:
        # If termination fails, we should not proceed to move the file as it might be locked.
        hydra_logger.logger.error("Aborting quarantine due to termination failure: {}".format(term_msg))
        return False, "Process termination failed: {}. File not moved.".format(term_msg)

    # 2. Move the file to quarantine
    move_success, move_msg = quarantine_file(file_path)

    if not move_success:
        return False, "{} | File move failed: {}".format(term_msg, move_msg)
        
    return True, "{} | {}".format(term_msg, move_msg)
