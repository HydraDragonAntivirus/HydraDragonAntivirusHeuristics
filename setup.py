from cx_Freeze import setup, Executable
import sys

# Build options
build_exe_options = {
    "packages": [
        "os", "math", "time", "json", "threading", "datetime", "re",
        "string", "traceback", "ctypes", "pathlib", "concurrent.futures",
        "psutil", "numpy", "pefile", "capstone", "hydra_logger", "quarantine"
    ],
    "includes": [
        "tkinter", "pe_feature_extractor"  # ensure tkinter and your helper are bundled
    ],
    "include_files": [],  # add extra data files if needed
}

# GUI base to hide console on Windows
base = "Win32GUI" if sys.platform == "win32" else None

setup(
    name="suspicious_file_scanner",
    version="1.0",
    description="HydraDragon Antivirus Heuristic Scanner",
    options={"build_exe": build_exe_options},
    executables=[Executable("suspicious_file_scanner.py", base=base)],
)
