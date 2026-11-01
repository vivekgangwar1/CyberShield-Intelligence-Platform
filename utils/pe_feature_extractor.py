
import os
import math
import pefile
import yara
from pathlib import Path
from collections import Counter

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
YARA_FILE = BASE_DIR / "utils" / "peid.yara"

# Compile YARA rules
YARA_RULES = yara.compile(filepath=str(YARA_FILE))

# Benign section names
BENIGN_SECTIONS = {
    ".text", ".data", ".rdata", ".idata",
    ".edata", ".rsrc", ".bss", ".crt", ".tls"
}


# Calculate file entropy
def calculate_entropy(data):

    if not data:
        return 0.0

    length = len(data)
    entropy = 0.0

    counts = Counter(data)

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


# Extract file version information
def get_fileinfo(pe):

    try:
        if not hasattr(pe, "FileInfo") or not pe.FileInfo:
            return 0

        for file_info_group in pe.FileInfo:

            for file_info in file_info_group:

                if not hasattr(file_info, "StringTable"):
                    continue

                for string_table in file_info.StringTable:

                    entries = string_table.entries

                    required = [
                        b"FileVersion",
                        b"ProductVersion",
                        b"ProductName",
                        b"CompanyName"
                    ]

                    if not all(key in entries for key in required):
                        return 0

                    if not hasattr(pe, "VS_FIXEDFILEINFO"):
                        return 0

                    if not pe.VS_FIXEDFILEINFO:
                        return 0

                    fixed = pe.VS_FIXEDFILEINFO[0]

                    _ = fixed.FileVersionLS
                    _ = fixed.FileVersionMS
                    _ = fixed.ProductVersionLS
                    _ = fixed.ProductVersionMS

                    return 1

        return 0

    except (AttributeError, IndexError, KeyError, TypeError):
        return 0


# Main PE feature extraction function
def extract_basic_pe_info(file_path):

    file_path = str(file_path)

    if not os.path.isfile(file_path):
        raise FileNotFoundError("File not found")

    pe = None

    try:

        # Read PE file
        pe = pefile.PE(file_path, fast_load=False)

        result = {}

        # --------------------------------
        # 1. DOS HEADER
        # --------------------------------

        dos_fields = [
            "e_cblp",
            "e_cp",
            "e_cparhdr",
            "e_maxalloc",
            "e_sp",
            "e_lfanew"
        ]

        for field in dos_fields:
            result[field] = getattr(pe.DOS_HEADER, field, 0)

        # --------------------------------
        # 2. FILE HEADER
        # --------------------------------

        result["NumberOfSections"] = pe.FILE_HEADER.NumberOfSections

        timestamp = pe.FILE_HEADER.TimeDateStamp

        year = 1970 + ((int(timestamp) / 86400) / 365)

        result["CreationYear"] = int(year in range(1980, 2016))

        file_header_flags = [
            pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED,
            pe.FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE,
            pe.FILE_HEADER.IMAGE_FILE_LINE_NUMS_STRIPPED,
            pe.FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED,
            pe.FILE_HEADER.IMAGE_FILE_AGGRESIVE_WS_TRIM,
            pe.FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE,
            pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_LO,
            pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE,
            pe.FILE_HEADER.IMAGE_FILE_DEBUG_STRIPPED,
            pe.FILE_HEADER.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
            pe.FILE_HEADER.IMAGE_FILE_NET_RUN_FROM_SWAP,
            pe.FILE_HEADER.IMAGE_FILE_SYSTEM,
            pe.FILE_HEADER.IMAGE_FILE_DLL,
            pe.FILE_HEADER.IMAGE_FILE_UP_SYSTEM_ONLY,
            pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_HI
        ]

        for i, value in enumerate(file_header_flags):
            result[f"FH_char{i}"] = int(value)

        # --------------------------------
        # 3. OPTIONAL HEADER
        # --------------------------------

        optional = pe.OPTIONAL_HEADER

        optional_fields = [
            "MajorLinkerVersion",
            "MinorLinkerVersion",
            "SizeOfCode",
            "SizeOfInitializedData",
            "SizeOfUninitializedData",
            "AddressOfEntryPoint",
            "BaseOfCode"
        ]

        for field in optional_fields:
            result[field] = getattr(optional, field, 0)

        result["BaseOfData"] = getattr(optional, "BaseOfData", 0)

        # ImageBase
        image_base = optional.ImageBase

        result["ImageBase"] = int(
            image_base % (64 * 1024) == 0
            and image_base in [268435456, 65536, 4194304]
        )

        # SectionAlignment
        section_alignment = optional.SectionAlignment
        file_alignment = optional.FileAlignment

        result["SectionAlignment"] = int(
            section_alignment >= file_alignment
        )

        # FileAlignment
        if section_alignment >= 512:

            file_alignment_flag = int(
                file_alignment % 2 == 0
                and 512 <= file_alignment <= 65536
            )

        else:

            file_alignment_flag = int(
                file_alignment == section_alignment
            )

        result["FileAlignment"] = file_alignment_flag

        remaining_fields = [
            "MajorOperatingSystemVersion",
            "MinorOperatingSystemVersion",
            "MajorImageVersion",
            "MinorImageVersion",
            "MajorSubsystemVersion",
            "MinorSubsystemVersion"
        ]

        for field in remaining_fields:
            result[field] = getattr(optional, field, 0)

        # SizeOfImage
        result["SizeOfImage"] = int(
            section_alignment != 0
            and optional.SizeOfImage % section_alignment == 0
        )

        # SizeOfHeaders
        result["SizeOfHeaders"] = int(
            file_alignment != 0
            and optional.SizeOfHeaders % file_alignment == 0
        )

        result["CheckSum"] = optional.CheckSum
        result["Subsystem"] = optional.Subsystem

        # --------------------------------
        # 4. DLL CHARACTERISTICS
        # --------------------------------

        dll_flags = [
            optional.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
            optional.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
            optional.IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
            optional.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
            optional.IMAGE_DLLCHARACTERISTICS_NO_SEH,
            optional.IMAGE_DLLCHARACTERISTICS_NO_BIND,
            optional.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
            optional.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
            optional.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
            optional.IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
            optional.IMAGE_DLLCHARACTERISTICS_GUARD_CF
        ]

        for i, value in enumerate(dll_flags):
            result[f"OH_DLLchar{i}"] = int(value)

        # Stack and Heap fields
        stack_heap_fields = [
            "SizeOfStackReserve",
            "SizeOfStackCommit",
            "SizeOfHeapReserve",
            "SizeOfHeapCommit"
        ]

        for field in stack_heap_fields:
            result[field] = getattr(optional, field, 0)

        result["LoaderFlags"] = int(optional.LoaderFlags == 0)

        # --------------------------------
        # 5. SECTION FEATURES
        # --------------------------------

        section_names = []

        for section in pe.sections:

            name = (
                section.Name.split(b"\x00")[0]
                .decode("ascii", errors="ignore")
            )

            section_names.append(name)

        non_sus_sections = len(
            set(section_names).intersection(BENIGN_SECTIONS)
        )

        result["sus_sections"] = (
            len(section_names) - non_sus_sections
        )

        result["non_sus_sections"] = non_sus_sections

        # --------------------------------
        # 6. PACKER DETECTION
        # --------------------------------

        matches = YARA_RULES.match(
            file_path,
            timeout=15
        )

        if matches:

            result["packer"] = 1
            result["packer_type"] = matches[0].rule

        else:

            result["packer"] = 0
            result["packer_type"] = "NoPacker"

        # --------------------------------
        # 7. TEXT AND DATA ENTROPY
        # --------------------------------

        result["E_text"] = 0.0
        result["E_data"] = 0.0

        for section in pe.sections:

            name = section.Name.split(b"\x00")[0]

            if name == b".text":
                result["E_text"] = section.get_entropy()

            elif name == b".data":
                result["E_data"] = section.get_entropy()

        # --------------------------------
        # 8. FILE SIZE AND ENTROPY
        # --------------------------------

        with open(file_path, "rb") as file:
            file_bytes = file.read()

        result["filesize"] = len(file_bytes)

        result["E_file"] = calculate_entropy(file_bytes)

        # --------------------------------
        # 9. VERSION INFORMATION
        # --------------------------------

        result["fileinfo"] = get_fileinfo(pe)

        return result

    except pefile.PEFormatError as error:

        raise ValueError(
            f"Invalid or unsupported PE file: {error}"
        )

    except yara.TimeoutError:

        raise RuntimeError("YARA scanning timed out")

    finally:

        if pe is not None:
            pe.close()
