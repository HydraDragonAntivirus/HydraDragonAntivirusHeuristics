import os
import hashlib
from hydra_logger import logger
import pefile
import numpy as np
import capstone
from typing import Dict, Any, List, Optional

# --- Globals ---
unified_pe_cache = {}
malicious_numeric_features = []
malicious_file_names = []
benign_numeric_features = []
benign_file_names = []


# --- PE Analysis and Feature Extraction Functions ---
class PEFeatureExtractor:
    def __init__(self):
        self.features_cache = {}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        # Use a more efficient way to get byte counts
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        total_bytes = len(data)

        # Filter out zero counts to avoid log(0)
        probs = counts[counts > 0] / total_bytes
        entropy = -np.sum(probs * np.log2(probs))

        return float(entropy)

    def disassemble_all_sections(self, pe) -> Dict[str, Any]:
        """
        Disassembles all sections of the PE file using Capstone and returns
        instruction counts and a packing heuristic for each section and the file overall.
        """
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
            if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I368']:
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
            logger.error("Capstone disassembly failed: {}".format(e))
            analysis['error'] = str(e)

        return analysis

    def extract_section_data(self, section) -> Dict[str, Any]:
        """Extract comprehensive section data including entropy."""
        raw_data = section.get_data()
        return {
            'name': section.Name.decode(errors='ignore').strip('\x00'),
            'virtual_size': section.Misc_VirtualSize,
            'virtual_address': section.VirtualAddress,
            'raw_size': section.SizeOfRawData,
            'pointer_to_raw_data': section.PointerToRawData,
            'characteristics': section.Characteristics,
            'entropy': self._calculate_entropy(raw_data),
            'raw_data_size': len(raw_data) if raw_data else 0
        }

    def extract_imports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed import information."""
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_imports = {
                    'dll_name': entry.dll.decode() if entry.dll else None,
                    'imports': [{
                        'name': imp.name.decode() if imp.name else None,
                        'address': imp.address,
                        'ordinal': imp.ordinal
                    } for imp in entry.imports]
                }
                imports.append(dll_imports)
        return imports

    def extract_exports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed export information."""
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    'name': exp.name.decode() if exp.name else None,
                    'address': exp.address,
                    'ordinal': exp.ordinal,
                    'forwarder': exp.forwarder.decode() if exp.forwarder else None
                }
                exports.append(export_info)
        return exports

    def _get_callback_addresses(self, pe, address_of_callbacks) -> List[int]:
        """Retrieve callback addresses from the TLS directory."""
        try:
            callback_addresses = []
            # Read callback addresses from the memory-mapped file
            while True:
                callback_address = pe.get_dword_at_rva(address_of_callbacks - pe.OPTIONAL_HEADER.ImageBase)
                if callback_address == 0:
                    break  # End of callback list
                callback_addresses.append(callback_address)
                address_of_callbacks += 4  # Move to the next address (4 bytes for DWORD)

            return callback_addresses
        except Exception as e:
            logger.error("Error retrieving TLS callback addresses: {}".format(e))
            return []

    def analyze_tls_callbacks(self, pe) -> Dict[str, Any]:
        """Analyze TLS (Thread Local Storage) callbacks and extract relevant details."""
        try:
            tls_callbacks = {}
            # Check if the PE file has a TLS directory
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                tls = pe.DIRECTORY_ENTRY_TLS.struct
                tls_callbacks = {
                    'start_address_raw_data': tls.StartAddressOfRawData,
                    'end_address_raw_data': tls.EndAddressOfRawData,
                    'address_of_index': tls.AddressOfIndex,
                    'address_of_callbacks': tls.AddressOfCallBacks,
                    'size_of_zero_fill': tls.SizeOfZeroFill,
                    'characteristics': tls.Characteristics,
                    'callbacks': []
                }

                # If there are callbacks, extract their addresses
                if tls.AddressOfCallBacks:
                    callback_array = self._get_callback_addresses(pe, tls.AddressOfCallBacks)
                    if callback_array:
                        tls_callbacks['callbacks'] = callback_array

            return tls_callbacks
        except Exception as e:
            logger.error("Error analyzing TLS callbacks: {}".format(e))
            return {}

    def analyze_dos_stub(self, pe) -> Dict[str, Any]:
        """Analyze DOS stub program."""
        try:
            dos_stub = {
                'exists': False,
                'size': 0,
                'entropy': 0.0,
            }

            if hasattr(pe, 'DOS_HEADER'):
                stub_offset = pe.DOS_HEADER.e_lfanew - 64  # Typical DOS stub starts after DOS header
                if stub_offset > 0:
                    dos_stub_data = pe.__data__[64:pe.DOS_HEADER.e_lfanew]
                    if dos_stub_data:
                        dos_stub['exists'] = True
                        dos_stub['size'] = len(dos_stub_data)
                        dos_stub['entropy'] = self._calculate_entropy(dos_stub_data)

            return dos_stub
        except Exception as e:
            logger.error("Error analyzing DOS stub: {}".format(e))
            return {}

    def analyze_certificates(self, pe) -> Dict[str, Any]:
        """Analyze security certificates."""
        try:
            cert_info = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                cert_info['virtual_address'] = pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress
                cert_info['size'] = pe.DIRECTORY_ENTRY_SECURITY.Size

                # Extract certificate attributes if available
                if hasattr(pe, 'VS_FIXEDFILEINFO'):
                    vs_info = pe.VS_FIXEDFILEINFO[0]
                    cert_info['fixed_file_info'] = {
                        'signature': vs_info.Signature,
                        'struct_version': vs_info.StrucVersion,
                        'file_version': "{}.{}.{}.{}".format(vs_info.FileVersionMS >> 16, vs_info.FileVersionMS & 0xFFFF, vs_info.FileVersionLS >> 16, vs_info.FileVersionLS & 0xFFFF),
                        'product_version': "{}.{}.{}.{}".format(vs_info.ProductVersionMS >> 16, vs_info.ProductVersionMS & 0xFFFF, vs_info.ProductVersionLS >> 16, vs_info.ProductVersionLS & 0xFFFF),
                        'file_flags': vs_info.FileFlags,
                        'file_os': vs_info.FileOS,
                        'file_type': vs_info.FileType,
                        'file_subtype': vs_info.FileSubtype,
                    }
            return cert_info
        except Exception as e:
            logger.error("Error analyzing certificates: {}".format(e))
            return {}

    def analyze_delay_imports(self, pe) -> List[Dict[str, Any]]:
        """Analyze delay-load imports with error handling for missing attributes."""
        try:
            delay_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    imports = []
                    for imp in entry.imports:
                        import_info = {
                            'name': imp.name.decode() if imp.name else None,
                            'address': imp.address,
                            'ordinal': imp.ordinal,
                        }
                        imports.append(import_info)

                    delay_import = {
                        'dll': entry.dll.decode() if entry.dll else None,
                        'attributes': getattr(entry.struct, 'Attributes', None),  # Use getattr for safe access
                        'name': getattr(entry.struct, 'Name', None),
                        'handle': getattr(entry.struct, 'Handle', None),
                        'iat': getattr(entry.struct, 'IAT', None),
                        'bound_iat': getattr(entry.struct, 'BoundIAT', None),
                        'unload_iat': getattr(entry.struct, 'UnloadIAT', None),
                        'timestamp': getattr(entry.struct, 'TimeDateStamp', None),
                        'imports': imports
                    }
                    delay_imports.append(delay_import)

            return delay_imports
        except Exception as e:
            logger.error("Error analyzing delay imports: {}".format(e))
            return []

    def analyze_load_config(self, pe) -> Dict[str, Any]:
        """Analyze load configuration."""
        try:
            load_config = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                load_config = {
                    'size': config.Size,
                    'timestamp': config.TimeDateStamp,
                    'major_version': config.MajorVersion,
                    'minor_version': config.MinorVersion,
                    'global_flags_clear': config.GlobalFlagsClear,
                    'global_flags_set': config.GlobalFlagsSet,
                    'critical_section_default_timeout': config.CriticalSectionDefaultTimeout,
                    'decommit_free_block_threshold': config.DeCommitFreeBlockThreshold,
                    'decommit_total_free_threshold': config.DeCommitTotalFreeThreshold,
                    'security_cookie': config.SecurityCookie,
                    'se_handler_table': config.SEHandlerTable,
                    'se_handler_count': config.SEHandlerCount
                }

            return load_config
        except Exception as e:
            logger.error("Error analyzing load config: {}".format(e))
            return {}

    def analyze_relocations(self, pe) -> List[Dict[str, Any]]:
        """Analyze base relocations with summarized entries."""
        try:
            relocations = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                    # Summarize relocation entries
                    entry_types = {}
                    offsets = []

                    for entry in base_reloc.entries:
                        entry_types[entry.type] = entry_types.get(entry.type, 0) + 1
                        offsets.append(entry.rva - base_reloc.struct.VirtualAddress)

                    reloc_info = {
                        'virtual_address': base_reloc.struct.VirtualAddress,
                        'size_of_block': base_reloc.struct.SizeOfBlock,
                        'summary': {
                            'total_entries': len(base_reloc.entries),
                            'types': entry_types,  # Counts of each relocation type
                            'offset_range': (min(offsets), max(offsets)) if offsets else None
                        }
                    }

                    relocations.append(reloc_info)

            return relocations
        except Exception as e:
            logger.error("Error analyzing relocations: {}".format(e))
            return []

    def analyze_bound_imports(self, pe) -> List[Dict[str, Any]]:
        """Analyze bound imports with robust error handling."""
        try:
            bound_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
                for bound_imp in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                    bound_import = {
                        'name': bound_imp.name.decode() if bound_imp.name else None,
                        'timestamp': bound_imp.struct.TimeDateStamp,
                        'references': []
                    }

                    # Check if `references` exists
                    if hasattr(bound_imp, 'references') and bound_imp.references:
                        for ref in bound_imp.references:
                            reference = {
                                'name': ref.name.decode() if ref.name else None,
                                'timestamp': getattr(ref.struct, 'TimeDateStamp', None)
                            }
                            bound_import['references'].append(reference)
                    else:
                        logger.warning("Bound import {} has no references.".format(bound_import['name']))

                    bound_imports.append(bound_import)

            return bound_imports
        except Exception as e:
            logger.error("Error analyzing bound imports: {}".format(e))
            return []

    def analyze_section_characteristics(self, pe) -> Dict[str, Dict[str, Any]]:
        """Analyze detailed section characteristics."""
        try:
            characteristics = {}
            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                flags = section.Characteristics

                # Decode section characteristics flags
                section_flags = {
                    'CODE': bool(flags & 0x20),
                    'INITIALIZED_DATA': bool(flags & 0x40),
                    'UNINITIALIZED_DATA': bool(flags & 0x80),
                    'MEM_DISCARDABLE': bool(flags & 0x2000000),
                    'MEM_NOT_CACHED': bool(flags & 0x4000000),
                    'MEM_NOT_PAGED': bool(flags & 0x8000000),
                    'MEM_SHARED': bool(flags & 0x10000000),
                    'MEM_EXECUTE': bool(flags & 0x20000000),
                    'MEM_READ': bool(flags & 0x40000000),
                    'MEM_WRITE': bool(flags & 0x80000000)
                }

                characteristics[section_name] = {
                    'flags': section_flags,
                    'entropy': self._calculate_entropy(section.get_data()),
                    'size_ratio': section.SizeOfRawData / pe.OPTIONAL_HEADER.SizeOfImage if pe.OPTIONAL_HEADER.SizeOfImage else 0,
                    'pointer_to_raw_data': section.PointerToRawData,
                    'pointer_to_relocations': section.PointerToRelocations,
                    'pointer_to_line_numbers': section.PointerToLinenumbers,
                    'number_of_relocations': section.NumberOfRelocations,
                    'number_of_line_numbers': section.NumberOfLinenumbers,
                }

            return characteristics
        except Exception as e:
            logger.error("Error analyzing section characteristics: {}".format(e))
            return {}

    def analyze_extended_headers(self, pe) -> Dict[str, Any]:
        """Analyze extended header information."""
        try:
            headers = {
                'dos_header': {
                    'e_magic': pe.DOS_HEADER.e_magic,
                    'e_cblp': pe.DOS_HEADER.e_cblp,
                    'e_cp': pe.DOS_HEADER.e_cp,
                    'e_crlc': pe.DOS_HEADER.e_crlc,
                    'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
                    'e_minalloc': pe.DOS_HEADER.e_minalloc,
                    'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
                    'e_ss': pe.DOS_HEADER.e_ss,
                    'e_sp': pe.DOS_HEADER.e_sp,
                    'e_csum': pe.DOS_HEADER.e_csum,
                    'e_ip': pe.DOS_HEADER.e_ip,
                    'e_cs': pe.DOS_HEADER.e_cs,
                    'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
                    'e_ovno': pe.DOS_HEADER.e_ovno,
                    'e_oemid': pe.DOS_HEADER.e_oemid,
                    'e_oeminfo': pe.DOS_HEADER.e_oeminfo
                },
                'nt_headers': {}
            }

            # Ensure NT_HEADERS exists and contains FileHeader
            if hasattr(pe, 'NT_HEADERS') and pe.NT_HEADERS is not None:
                nt_headers = pe.NT_HEADERS
                if hasattr(nt_headers, 'FileHeader'):
                    headers['nt_headers'] = {
                        'signature': nt_headers.Signature,
                        'machine': nt_headers.FileHeader.Machine,
                        'number_of_sections': nt_headers.FileHeader.NumberOfSections,
                        'time_date_stamp': nt_headers.FileHeader.TimeDateStamp,
                        'characteristics': nt_headers.FileHeader.Characteristics
                    }

            return headers
        except Exception as e:
            logger.error("Error analyzing extended headers: {}".format(e))
            return {}

    def serialize_data(self, data) -> Any:
        """Serialize data for output, ensuring compatibility."""
        try:
            return list(data) if data else None
        except Exception:
            return None

    def analyze_rich_header(self, pe) -> Dict[str, Any]:
        """Analyze Rich header details."""
        try:
            rich_header = {}
            if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER is not None:
                rich_header['checksum'] = getattr(pe.RICH_HEADER, 'checksum', None)
                rich_header['values'] = self.serialize_data(pe.RICH_HEADER.values)
                rich_header['clear_data'] = self.serialize_data(pe.RICH_HEADER.clear_data)
                rich_header['key'] = self.serialize_data(pe.RICH_HEADER.key)
                rich_header['raw_data'] = self.serialize_data(pe.RICH_HEADER.raw_data)

                # Decode CompID and build number information
                compid_info = []
                if rich_header['values']:
                    for i in range(0, len(rich_header['values']), 2):
                        if i + 1 < len(rich_header['values']):
                            comp_id = rich_header['values'][i] >> 16
                            build_number = rich_header['values'][i] & 0xFFFF
                            count = rich_header['values'][i + 1]
                            compid_info.append({
                                'comp_id': comp_id,
                                'build_number': build_number,
                                'count': count
                            })
                rich_header['comp_id_info'] = compid_info

            return rich_header
        except Exception as e:
            logger.error("Error analyzing Rich header: {}".format(e))
            return {}

    def analyze_overlay(self, pe, file_path: str) -> Dict[str, Any]:
        """Analyze file overlay (data appended after the PE structure)."""
        try:
            overlay_info = {
                'exists': False,
                'offset': 0,
                'size': 0,
                'entropy': 0.0
            }

            # Calculate the end of the PE structure
            if not pe.sections:
                 return overlay_info

            last_section = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
            end_of_pe = last_section.PointerToRawData + last_section.SizeOfRawData

            # Get file size
            file_size = os.path.getsize(file_path)

            # Check for overlay
            if file_size > end_of_pe:
                with open(file_path, 'rb') as f:
                    f.seek(end_of_pe)
                    overlay_data = f.read()

                    overlay_info['exists'] = True
                    overlay_info['offset'] = end_of_pe
                    overlay_info['size'] = len(overlay_data)
                    overlay_info['entropy'] = self._calculate_entropy(overlay_data)

            return overlay_info
        except Exception as e:
            logger.error("Error analyzing overlay: {}".format(e))
            return {}

    def extract_numeric_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Extract numeric features of a file using pefile.
        Ensures pefile.PE is closed even on exceptions to avoid leaking file handles on Windows.
        """
        pe = None
        try:

            try:
                # Attempt to load PE file directly
                pe = pefile.PE(file_path, fast_load=True)
            except pefile.PEFormatError:
                logger.error("{} is not a valid PE file.".format(file_path))
                return None
            except Exception as ex:
                logger.error("Error loading {} as PE: {}".format(file_path, str(ex)), exc_info=True)
                return None
            try:
                pe.parse_data_directories()
            except Exception:
                logger.debug("pe.parse_data_directories() failed for {}".format(file_path), exc_info=True)

            # Extract features
            numeric_features = {
                # Capstone analysis for packing
                'section_disassembly': self.disassemble_all_sections(pe),

                # Optional Header Features
                'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
                'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
                'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
                'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
                'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
                'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
                'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
                'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
                'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
                'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
                'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
                'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
                'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
                'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
                'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,

                # Section Headers
                'sections': [
                    {
                        'name': section.Name.decode(errors='ignore').strip('\x00'),
                        'virtual_size': section.Misc_VirtualSize,
                        'virtual_address': section.VirtualAddress,
                        'size_of_raw_data': section.SizeOfRawData,
                        'pointer_to_raw_data': section.PointerToRawData,
                        'characteristics': section.Characteristics,
                    }
                    for section in pe.sections
                ],

                # Imported Functions
                'imports': [
                    imp.name.decode(errors='ignore') if imp.name else "Unknown"
                    for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
                    for imp in getattr(entry, 'imports', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],

                # Exported Functions
                'exports': [
                    exp.name.decode(errors='ignore') if exp.name else "Unknown"
                    for exp in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],

                # Resources
                'resources': [
                    {
                        'type_id': getattr(getattr(resource_type, 'struct', None), 'Id', None),
                        'resource_id': getattr(getattr(resource_id, 'struct', None), 'Id', None),
                        'lang_id': getattr(getattr(resource_lang, 'struct', None), 'Id', None),
                        'size': getattr(getattr(resource_lang, 'data', None), 'Size', None),
                        'codepage': getattr(getattr(resource_lang, 'data', None), 'CodePage', None),
                    }
                    for resource_type in
                    (pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries') else [])
                    for resource_id in (resource_type.directory.entries if hasattr(resource_type, 'directory') else [])
                    for resource_lang in (resource_id.directory.entries if hasattr(resource_id, 'directory') else [])
                    if hasattr(resource_lang, 'data')
                ] if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else [],

                # Debug Information
                'debug': [
                    {
                        'type': debug.struct.Type,
                        'timestamp': debug.struct.TimeDateStamp,
                        'version': "{}.{}".format(debug.struct.MajorVersion, debug.struct.MinorVersion),
                        'size': debug.struct.SizeOfData,
                    }
                    for debug in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else [],

                # Certificates
                'certificates': self.analyze_certificates(pe),  # Analyze certificates

                # DOS Stub Analysis
                'dos_stub': self.analyze_dos_stub(pe),  # DOS stub analysis here

                # TLS Callbacks
                'tls_callbacks': self.analyze_tls_callbacks(pe),  # TLS callback analysis here

                # Delay Imports
                'delay_imports': self.analyze_delay_imports(pe),  # Delay imports analysis here

                # Load Config
                'load_config': self.analyze_load_config(pe),  # Load config analysis here

                # Bound Imports
                'bound_imports': self.analyze_bound_imports(pe),  # Bound imports analysis here

                # Section Characteristics
                'section_characteristics': self.analyze_section_characteristics(pe),
                # Section characteristics analysis here

                # Extended Headers
                'extended_headers': self.analyze_extended_headers(pe),  # Extended headers analysis here

                # Rich Header
                'rich_header': self.analyze_rich_header(pe),  # Rich header analysis here

                # Overlay
                'overlay': self.analyze_overlay(pe, file_path),  # Overlay analysis here

                #Relocations
                'relocations': self.analyze_relocations(pe) #Relocations analysis here
            }

            # Add numeric tag if provided
            if rank is not None:
                numeric_features['numeric_tag'] = rank

            return numeric_features

        except Exception as ex:
            logger.error("Error extracting numeric features from {}: {}".format(file_path, str(ex)), exc_info=True)
            return None
        finally:
            # ensure PE handle is closed to release underlying file descriptor
            try:
                if pe is not None:
                    pe.close()
            except Exception:
                logger.debug("Failed to close pe for {}".format(file_path), exc_info=True)

pe_extractor = PEFeatureExtractor()

# --- Caching and Feature Extraction ---
def compute_md5(file_path):
    """Computes MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        logger.error("Could not compute MD5 for {}: {}".format(file_path, e))
        return None

def get_cached_pe_features(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Extract and cache PE file numeric features with unified caching.
    Returns cached features if available, otherwise extracts and caches them.
    Used by both ML scanning and worm detection.
    """
    # Calculate MD5 hash for caching
    file_md5 = compute_md5(file_path)
    if not file_md5:
        return None

    # Check if we already have features for this MD5
    if file_md5 in unified_pe_cache:
        logger.debug("Using cached features for {} (MD5: {})".format(file_path, file_md5))
        return unified_pe_cache[file_md5]

    try:
        # Extract numeric features
        features = pe_extractor.extract_numeric_features(file_path)
        if features:
            # Cache the result with MD5 as key
            unified_pe_cache[file_md5] = features
            logger.debug("Cached features for {} (MD5: {})".format(file_path, file_md5))
            return features
        else:
            # Cache negative result too to avoid re-processing failed files
            unified_pe_cache[file_md5] = None
            return None

    except Exception as ex:
        logger.error("An error occurred while processing {}: {}".format(file_path, ex), exc_info=True)
        # Cache the failure to avoid repeated attempts
        unified_pe_cache[file_md5] = None
        return None
