#!/usr/bin/env -S python3 -I -S
## @file
# Generate an FFS file from one or more section files.
#
# Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
"""
GenFfs.py - Pure-Python implementation of the EDK2 BaseTools GenFfs utility.

It replaces the former C tool (BaseTools/Source/C/GenFfs): same options, same
output bytes, same console messages, same exit codes (0 = success, 2 = error).

  Command line (fastest):  python3 -I -S GenFfs.py <GenFfs options>
  In-process:              import GenFfs; rc = GenFfs.main([...args...])

Startup-time design: the GenFfs code lives in the _CORE block below. Python only
has to tokenize it as one string literal (~0.3 ms instead of ~5.6 ms to compile);
its compiled bytecode is cached in __pycache__/ next to this file, keyed on this
file's size, mtime and the Python version, and recompiled automatically after
edits. If __pycache__ cannot be written, it simply compiles every run.
Edit the code inside _CORE like normal Python; tracebacks show real line numbers.
"""
import sys
import marshal

_CORE_LINE = sys._getframe().f_lineno + 1
_CORE = r'''
import sys

try:
    import posix as _os          # Linux / macOS / *BSD
except ImportError:              # pragma: no cover
    import nt as _os             # Windows

UTILITY_NAME = "GenFfs"
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1
BUILD_VERSION = "Developer Build based on Revision: Unknown"

STATUS_SUCCESS = 0
STATUS_ERROR = 2

VERBOSE_LOG_LEVEL = 15
WARNING_LOG_LEVEL = 15
INFO_LOG_LEVEL = 20
KEY_LOG_LEVEL = 40
MAX_LINE_LEN = 0x200

EFI_FV_FILETYPE_ALL = 0x00
EFI_FV_FILETYPE_SECURITY_CORE = 0x03
EFI_FV_FILETYPE_PEI_CORE = 0x04
EFI_FV_FILETYPE_DXE_CORE = 0x05
EFI_FV_FILETYPE_PEIM = 0x06
EFI_FV_FILETYPE_DRIVER = 0x07
EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER = 0x08
EFI_FV_FILETYPE_APPLICATION = 0x09

FFS_ATTRIB_LARGE_FILE = 0x01
FFS_ATTRIB_DATA_ALIGNMENT2 = 0x02
FFS_ATTRIB_FIXED = 0x04
FFS_ATTRIB_CHECKSUM = 0x40

FFS_STATE = 0x07   # EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID | EFI_FILE_DATA_VALID
FFS_FIXED_CHECKSUM = 0xAA
MAX_FFS_SIZE = 0x1000000
MAX_SECTION_SIZE = 0x1000000

SIZEOF_FFS_HEADER = 24
SIZEOF_FFS_HEADER2 = 32
SIZEOF_SECTION_HEADER = 4
SIZEOF_SECTION_HEADER2 = 8
SIZEOF_FREEFORM_SUBTYPE_GUID_SECTION = 20
SIZEOF_TE_IMAGE_HEADER = 40
PROBE_BYTES = 48                  # largest header GetSectionContents ever looks at

EFI_SECTION_COMPRESSION = 0x01
EFI_SECTION_GUID_DEFINED = 0x02
EFI_SECTION_PE32 = 0x10
EFI_SECTION_TE = 0x12
EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
EFI_SECTION_FREEFORM_SUBTYPE_GUID = 0x18
EFI_SECTION_RAW = 0x19

EFI_TE_IMAGE_HEADER_SIGNATURE = 0x5A56      # "VZ"
EFI_IMAGE_DOS_SIGNATURE = 0x5A4D            # "MZ"
EFI_IMAGE_NT_SIGNATURE = 0x00004550         # "PE\0\0"
SUPPORTED_MACHINES = (0x014C, 0x8664, 0x0EBC, 0xAA64, 0x5064, 0x6264)
SUPPORTED_SUBSYSTEMS = (10, 11, 12)
RETURN_UNSUPPORTED = 3

# EFI_FFS_SECTION_ALIGNMENT_PADDING_GUID {04132C8D-0A22-4FA8-826E-8BBFEFDB836C}
PADDING_GUID = bytes((0x8D, 0x2C, 0x13, 0x04, 0x22, 0x0A, 0xA8, 0x4F,
                      0x82, 0x6E, 0x8B, 0xBF, 0xEF, 0xDB, 0x83, 0x6C))

M_FFS_FILE_TYPE = (
    None,
    "EFI_FV_FILETYPE_RAW",
    "EFI_FV_FILETYPE_FREEFORM",
    "EFI_FV_FILETYPE_SECURITY_CORE",
    "EFI_FV_FILETYPE_PEI_CORE",
    "EFI_FV_FILETYPE_DXE_CORE",
    "EFI_FV_FILETYPE_PEIM",
    "EFI_FV_FILETYPE_DRIVER",
    "EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER",
    "EFI_FV_FILETYPE_APPLICATION",
    "EFI_FV_FILETYPE_SMM",
    "EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE",
    "EFI_FV_FILETYPE_COMBINED_SMM_DXE",
    "EFI_FV_FILETYPE_SMM_CORE",
    "EFI_FV_FILETYPE_MM_STANDALONE",
    "EFI_FV_FILETYPE_MM_CORE_STANDALONE",
)
_FILE_TYPE_LOOKUP = {n.lower(): i for i, n in enumerate(M_FFS_FILE_TYPE) if n}

M_ALIGN_NAME = ("1", "2", "4", "8", "16", "32", "64", "128", "256", "512",
                "1K", "2K", "4K", "8K", "16K", "32K", "64K", "128K", "256K",
                "512K", "1M", "2M", "4M", "8M", "16M")
_ALIGN_LOOKUP = {n.lower(): 1 << i for i, n in enumerate(M_ALIGN_NAME)}

M_FFS_VALID_ALIGN_NAME = ("8", "16", "128", "512", "1K", "4K", "32K", "64K", "128K",
                          "256K", "512K", "1M", "2M", "4M", "8M", "16M")
_FFS_ALIGN_LOOKUP = {n.lower(): i for i, n in enumerate(M_FFS_VALID_ALIGN_NAME)}

M_FFS_VALID_ALIGN = (0, 8, 16, 128, 512, 1024, 4096, 32768, 65536, 131072, 262144,
                     524288, 1048576, 2097152, 4194304, 8388608, 16777216)

U32 = 0xFFFFFFFF
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _ieq(a, b):
    """stricmp(a, b) == 0"""
    return a is not None and a.lower() == b


def _u16(buf, off):
    return int.from_bytes(buf[off:off + 2].ljust(2, b"\0"), "little")


def _u32(buf, off):
    return int.from_bytes(buf[off:off + 4].ljust(4, b"\0"), "little")


def _checksum8(data):
    """CalculateChecksum8(): (0x100 - sum of bytes) & 0xFF."""
    n = len(data)
    if n < 0x4000:
        s = sum(data)
    else:
        # sum(bytes) mod 256 computed in C via zlib.adler32 on 256-byte chunks:
        # each chunk's byte sum is < 65521, so adler's low half is exact (+1),
        # and the high halves only add multiples of 65536 (no effect mod 256).
        import zlib
        mv = memoryview(data)
        starts = range(0, n, 256)
        s = sum(map(zlib.adler32,
                    map(mv.__getitem__, map(slice, starts, range(256, n + 256, 256))))) \
            - len(starts)
    return (0x100 - (s & 0xFF)) & 0xFF


def c_format(fmt, *args):
    """Tiny printf: %s %d %i %u %x %X %c %% with flags/width (what GenFfs uses).

    Conversions without a matching argument (format strings that come from user
    data, as in the C tool) are emitted literally.
    """
    if "%" not in fmt:
        return fmt
    out = []
    ai = 0
    i = 0
    n = len(fmt)
    while i < n:
        j = fmt.find("%", i)
        if j < 0:
            out.append(fmt[i:])
            break
        out.append(fmt[i:j])
        k = j + 1
        while k < n and fmt[k] in "-0 +#":
            k += 1
        flags = fmt[j + 1:k]
        ws = k
        while k < n and fmt[k].isdigit():
            k += 1
        width = int(fmt[ws:k]) if k > ws else 0
        if k < n and fmt[k] == ".":
            p = k + 1
            while p < n and fmt[p].isdigit():
                p += 1
            if p > k + 1:
                k = p
        for mod in ("hh", "ll", "h", "l", "z"):
            if fmt.startswith(mod, k):
                k += len(mod)
                break
        if k >= n or fmt[k] not in "diuxXcs%":
            out.append("%")
            i = j + 1
            continue
        conv = fmt[k]
        spec = fmt[j:k + 1]
        i = k + 1
        if conv == "%":
            out.append("%")
            continue
        if ai >= len(args):
            out.append(spec)
            continue
        a = args[ai]
        ai += 1
        if conv == "s":
            s = "(null)" if a is None else str(a)
        elif conv == "c":
            s = chr(a)
        elif conv in "di":
            v = int(a) & U32
            s = str(v - (1 << 32) if v & 0x80000000 else v)
        elif conv == "u":
            s = str(int(a) & U32)
        elif conv == "x":
            s = "%x" % (int(a) & U32)
        else:
            s = "%X" % (int(a) & U32)
        if len(s) < width:
            if "-" in flags:
                s = s.ljust(width)
            elif "0" in flags and conv != "s":
                s = ("-" + s[1:].rjust(width - 1, "0")) if s[0] == "-" else s.rjust(width, "0")
            else:
                s = s.rjust(width)
        out.append(s)
    return "".join(out)


# ---------------------------------------------------------------------------
# EfiUtilityMsgs port
# ---------------------------------------------------------------------------
class Msgs:
    __slots__ = ("w", "status", "level")

    def __init__(self, out):
        self.w = out.write
        self.status = STATUS_SUCCESS
        self.level = INFO_LOG_LEVEL

    def _print(self, mtype, code, text, fmt, args):
        if mtype == "DEBUG":
            import time
            t = time.localtime()
            self.w("%04d-%02d-%02d %02d:%02d:%02d" % (
                t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec))
            line = ""
        else:
            line = UTILITY_NAME
            if mtype == "ERROR" and self.status < STATUS_ERROR:
                self.status = STATUS_ERROR
        line += ": " + mtype
        if code:
            line += " %04u" % code
        self.w(line)
        if text is not None:
            self.w(": %s" % text)
        self.w("\n")
        if fmt is not None:
            self.w("  %s\n" % c_format(fmt, *args)[:MAX_LINE_LEN - 1])

    def error(self, code, text, fmt, *args):
        self._print("ERROR", code, text, fmt, args)

    def warning(self, code, text, fmt, *args):
        if WARNING_LOG_LEVEL >= self.level:
            self._print("WARNING", code, text, fmt, args)

    def debug(self, level, text, fmt, *args):
        if level >= self.level:
            self._print("DEBUG", 0, text, fmt, args)

    def verbose(self, fmt, *args):
        if VERBOSE_LOG_LEVEL >= self.level:
            self.w("%s\n" % c_format(fmt, *args)[:MAX_LINE_LEN - 1])

    def key(self, fmt, *args):
        if KEY_LOG_LEVEL >= self.level:
            self.w("%s\n" % c_format(fmt, *args)[:MAX_LINE_LEN - 1])


# ---------------------------------------------------------------------------
# ParseInf.c ports
# ---------------------------------------------------------------------------
def string_to_guid(msgs, s):
    if s is None:
        return None
    ok = len(s) == 36
    if ok:
        for i, ch in enumerate(s):
            if i in (8, 13, 18, 23):
                if ch != "-":
                    ok = False
                    break
            elif ch not in _HEXDIGITS:
                ok = False
                break
    if not ok:
        msgs.error(1003, "Invalid option value",
                   "Incorrect GUID \"%s\"\n  Correct Format "
                   "\"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\"", s)
        return None
    return (int(s[0:8], 16).to_bytes(4, "little")
            + int(s[9:13], 16).to_bytes(2, "little")
            + int(s[14:18], 16).to_bytes(2, "little")
            + bytes.fromhex(s[19:23] + s[24:36]))


def ascii_string_to_uint64(s):
    """AsciiStringToUint64(s, FALSE, ...) -> value or None."""
    if s is None or len(s.encode("utf-8", "surrogateescape")) > 0xFF:
        return None
    i = 0
    n = len(s)
    while i < n and s[i] == " ":
        i += 1
    is_hex = False
    if s[i:i + 2] in ("0x", "0X"):
        is_hex = True
        i += 2
    v = 0
    while i < n:
        ch = s[i]
        if ch == " ":
            break
        if is_hex:
            if ch not in _HEXDIGITS:
                return None
            v = (v * 16 + int(ch, 16)) & 0xFFFFFFFFFFFFFFFF
        else:
            if not ("0" <= ch <= "9"):
                return None
            v = (v * 10 + ord(ch) - 48) & 0xFFFFFFFFFFFFFFFF
        i += 1
    return v


# ---------------------------------------------------------------------------
# BasePeCoff.c (PeCoffLoaderGetImageInfo: only SectionAlignment is needed)
# ---------------------------------------------------------------------------
def _pe_section_alignment(img):
    pe = 0
    if _u16(img, 0) == EFI_IMAGE_DOS_SIGNATURE:
        pe = _u32(img, 0x3C)
    if _u32(img, pe) != EFI_IMAGE_NT_SIGNATURE:
        if _u16(img, pe) != EFI_TE_IMAGE_HEADER_SIGNATURE:
            return RETURN_UNSUPPORTED, 0
        machine = _u16(img, pe + 2)
        subsystem = img[pe + 5] if pe + 5 < len(img) else 0
        te = True
    else:
        machine = _u16(img, pe + 4)
        subsystem = _u16(img, pe + 24 + 68)
        te = False
    if machine not in SUPPORTED_MACHINES or subsystem not in SUPPORTED_SUBSYSTEMS:
        return RETURN_UNSUPPORTED, 0
    if te:
        return 0, 4096
    return 0, _u32(img, pe + 24 + 32)   # same offset for PE32 and PE32+


def get_alignment_from_file(msgs, name):
    try:
        f = open(name, "rb")
    except OSError:
        msgs.error(1, "Error opening file", name)
        return None
    with f:
        head = f.read(0x1000)
        hdr = SIZEOF_SECTION_HEADER2 if (_u32(head, 0) & 0xFFFFFF) == 0xFFFFFF \
            else SIZEOF_SECTION_HEADER
        img = head[hdr:]
        if len(head) == 0x1000:
            pe = _u32(img, 0x3C) if _u16(img, 0) == EFI_IMAGE_DOS_SIGNATURE else 0
            if pe + 0x100 > len(img):          # PE header beyond the first 4K
                img = img + f.read()
    status, align = _pe_section_alignment(img)
    if status:
        msgs.error(3000, "Invalid PeImage",
                   "The input file is %s and return status is %x", name, status)
        return None
    return align


# ---------------------------------------------------------------------------
# GenFfs.c
# ---------------------------------------------------------------------------
def version(w):
    w("%s Version %d.%d %s \n" % (UTILITY_NAME, UTILITY_MAJOR_VERSION,
                                 UTILITY_MINOR_VERSION, BUILD_VERSION))


USAGE = (
    "\nUsage: GenFfs [options]\n\n"
    "Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.\n\n"
    "Options:\n"
    "  -o FileName, --outputfile FileName\n"
    "                        File is FFS file to be created.\n"
    "  -t Type, --filetype Type\n"
    "                        Type is one FV file type defined in PI spec, which is\n"
    "                        EFI_FV_FILETYPE_RAW, EFI_FV_FILETYPE_FREEFORM,\n"
    "                        EFI_FV_FILETYPE_SECURITY_CORE, EFI_FV_FILETYPE_PEIM,\n"
    "                        EFI_FV_FILETYPE_PEI_CORE, EFI_FV_FILETYPE_DXE_CORE,\n"
    "                        EFI_FV_FILETYPE_DRIVER, EFI_FV_FILETYPE_APPLICATION,\n"
    "                        EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER,\n"
    "                        EFI_FV_FILETYPE_SMM, EFI_FV_FILETYPE_SMM_CORE,\n"
    "                        EFI_FV_FILETYPE_MM_STANDALONE,\n"
    "                        EFI_FV_FILETYPE_MM_CORE_STANDALONE,\n"
    "                        EFI_FV_FILETYPE_COMBINED_SMM_DXE, \n"
    "                        EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE.\n"
    "  -g FileGuid, --fileguid FileGuid\n"
    "                        FileGuid is one module guid.\n"
    "                        Its format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\n"
    "  -x, --fixed           Indicates that the file may not be moved\n"
    "                        from its present location.\n"
    "  -s, --checksum        Indicates to calculate file checksum.\n"
    "  -a FileAlign, --align FileAlign\n"
    "                        FileAlign points to file alignment, which only support\n"
    "                        the following align: 1,2,4,8,16,128,512,1K,4K,32K,64K\n"
    "                        128K,256K,512K,1M,2M,4M,8M,16M\n"
    "  -i SectionFile, --sectionfile SectionFile\n"
    "                        Section file will be contained in this FFS file.\n"
    "  -oi SectionFile, --optionalsectionfile SectionFile\n"
    "                        If the Section file exists, it will be contained in this "
    "FFS file, otherwise, it will be ignored.\n"
    "  -n SectionAlign, --sectionalign SectionAlign\n"
    "                        SectionAlign points to section alignment, which support\n"
    "                        the alignment scope 0~16M. If SectionAlign is specified\n"
    "                        as 0, tool get alignment value from SectionFile. It is\n"
    "                        specified together with sectionfile to point its\n"
    "                        alignment in FFS file.\n"
    "  -v, --verbose         Turn on verbose output with informational messages.\n"
    "  -q, --quiet           Disable all messages except key message and fatal error\n"
    "  -d, --debug level     Enable debug messages, at input debug level.\n"
    "  --version             Show program's version number and exit.\n"
    "  -h, --help            Show this help message and exit.\n"
)

EFI_SUCCESS = 0
EFI_ABORTED = 1
EFI_BUFFER_TOO_SMALL = 2


def get_section_contents(msgs, names, aligns, ffs_attrib, buf, buf_len, pe_num):
    """GetSectionContents(). buf is None (size pass) or a zeroed bytearray(buf_len).

    Returns (status, length, max_alignment, pe_section_num).
    """
    size = 0
    max_enc = 1
    mv = memoryview(buf) if buf is not None else None

    for index, name in enumerate(names):
        size = (size + 3) & ~3

        try:
            f = open(name, "rb", buffering=0)
        except OSError:
            msgs.error(1, "Error opening file", name)
            return EFI_ABORTED, buf_len, 1, pe_num
        with f:
            file_size = _os.fstat(f.fileno()).st_size & U32
            msgs.debug(9, "Input section files",
                       "the input section name is %s and the size is %u bytes",
                       name, file_size)
            head = f.read(PROBE_BYTES)

            te_off = 0
            hsz = SIZEOF_SECTION_HEADER2 if file_size >= MAX_FFS_SIZE else SIZEOF_SECTION_HEADER
            stype = head[3] if len(head) > 3 else 0
            if stype == EFI_SECTION_TE:
                pe_num = (pe_num + 1) & 0xFF
                te = head[hsz:hsz + SIZEOF_TE_IMAGE_HEADER]
                if _u16(te, 0) == EFI_TE_IMAGE_HEADER_SIGNATURE:
                    te_off = (_u16(te, 6) - SIZEOF_TE_IMAGE_HEADER) & U32
            elif stype == EFI_SECTION_PE32:
                pe_num = (pe_num + 1) & 0xFF
            elif stype == EFI_SECTION_GUID_DEFINED:
                if file_size >= MAX_SECTION_SIZE:
                    if not (_u16(head, 26) & 1):        # PROCESSING_REQUIRED
                        hsz = _u16(head, 24)
                else:
                    if not (_u16(head, 22) & 1):
                        hsz = _u16(head, 20)
                pe_num = (pe_num + 1) & 0xFF
            elif stype == EFI_SECTION_COMPRESSION or stype == EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
                pe_num = (pe_num + 1) & 0xFF

            align = aligns[index]
            if te_off and align:
                te_off = ((align - te_off % align) & U32) % align

            if align and (size + hsz + te_off) % align:
                off = ((size + SIZEOF_SECTION_HEADER + hsz + te_off + align - 1) & ~(align - 1)) & U32
                off = (off - size - hsz - te_off) & U32
                if buf is not None and size + off < buf_len:
                    # buffer is pre-zeroed (memset in C)
                    buf[size] = off & 0xFF
                    buf[size + 1] = (off >> 8) & 0xFF
                    buf[size + 2] = (off >> 16) & 0xFF
                    if (ffs_attrib & FFS_ATTRIB_FIXED and max_enc <= 1
                            and off >= SIZEOF_FREEFORM_SUBTYPE_GUID_SECTION):
                        buf[size + 3] = EFI_SECTION_FREEFORM_SUBTYPE_GUID
                        buf[size + 4:size + 20] = PADDING_GUID
                    else:
                        buf[size + 3] = EFI_SECTION_RAW
                msgs.debug(9, "Pad raw section for section data alignment",
                           "Pad Raw section size is %u", off)
                size = (size + off) & U32

            if max_enc < align:
                max_enc = align

            if file_size and buf is not None and size + file_size <= buf_len:
                f.seek(0)
                dst = mv[size:size + file_size]
                got = f.readinto(dst)
                while got and got < file_size:
                    r = f.readinto(dst[got:])
                    if not r:
                        break
                    got += r
                if got != file_size:
                    msgs.error(4, "Error reading file", name)
                    return EFI_ABORTED, buf_len, max_enc, pe_num

        size = (size + file_size) & U32

    if size > buf_len:
        return EFI_BUFFER_TOO_SMALL, size, max_enc, pe_num
    return EFI_SUCCESS, size, max_enc, pe_num


def main(argv=None, out=None):
    """Run GenFfs. argv excludes the program name. Returns the exit code."""
    if argv is None:
        argv = sys.argv[1:]
    if out is None:
        out = sys.stdout
    w = out.write
    msgs = Msgs(out)

    ffs_attrib = 0
    ffs_align = 0
    ffs_type = EFI_FV_FILETYPE_ALL
    out_name = None
    guid = bytes(16)
    names = []
    aligns = []

    argc = len(argv)
    if argc == 0:
        msgs.error(1001, "Missing options", "no options input")
        w(USAGE)
        return STATUS_ERROR

    args = list(argv)
    args.append(None)      # C argv[] is NULL terminated
    args.append(None)

    first = args[0].lower()
    if first == "-h" or first == "--help":
        version(w)
        w(USAGE)
        return STATUS_SUCCESS
    if first == "--version":
        version(w)
        return STATUS_SUCCESS

    def finish():
        msgs.verbose("%s tool done with return code is 0x%x.", UTILITY_NAME, msgs.status)
        return msgs.status

    i = 0
    while argc > 0:
        a0 = args[i].lower()
        a1 = args[i + 1]

        if a0 == "-t" or a0 == "--filetype":
            if a1 is None or a1[:1] == "-":
                msgs.error(1003, "Invalid option value", "file type is missing for -t option")
                return finish()
            ffs_type = _FILE_TYPE_LOOKUP.get(a1.lower(), EFI_FV_FILETYPE_ALL)
            if ffs_type == EFI_FV_FILETYPE_ALL:
                msgs.error(1003, "Invalid option value", "%s is not a valid file type", a1)
                return finish()
            argc -= 2
            i += 2
            continue

        if a0 == "-o" or a0 == "--outputfile":
            if a1 is None or a1[:1] == "-":
                msgs.error(1003, "Invalid option value", "Output file is missing for -o option")
                return finish()
            out_name = a1
            argc -= 2
            i += 2
            continue

        if a0 == "-g" or a0 == "--fileguid":
            g = string_to_guid(msgs, a1)
            if g is None:
                msgs.error(1003, "Invalid option value", "%s = %s", args[i], a1)
                return finish()
            guid = g
            argc -= 2
            i += 2
            continue

        if a0 == "-x" or a0 == "--fixed":
            ffs_attrib |= FFS_ATTRIB_FIXED
            argc -= 1
            i += 1
            continue

        if a0 == "-s" or a0 == "--checksum":
            ffs_attrib |= FFS_ATTRIB_CHECKSUM
            argc -= 1
            i += 1
            continue

        if a0 == "-a" or a0 == "--align":
            if a1 is None or a1[:1] == "-":
                msgs.error(1003, "Invalid option value", "Align value is missing for -a option")
                return finish()
            idx = _FFS_ALIGN_LOOKUP.get(a1.lower())
            if idx is None:
                if a1 in ("1", "2", "4"):
                    idx = 0          # 1, 2, 4 byte alignment same to 8 byte alignment
                else:
                    msgs.error(1003, "Invalid option value", "%s = %s", args[i], a1)
                    return finish()
            ffs_align = idx
            argc -= 2
            i += 2
            continue

        if a0 == "-i" or a0 == "--sectionfile" or a0 == "-oi" or a0 == "--optionalsectionfile":
            if a1 is None or a1[:1] == "-":
                msgs.error(1003, "Invalid option value",
                           "input section file is missing for -i option")
                return finish()
            if a0 == "-oi" or a0 == "--optionalsectionfile":
                try:
                    exists = _os.access(a1, 0)
                except (OSError, ValueError):
                    exists = False
                if not exists:
                    msgs.warning(1, "File is not found.", a1)
                    argc -= 2
                    i += 2
                    continue
            names.append(a1)
            aligns.append(0)
            argc -= 2
            i += 2
            if argc <= 0:
                break
            a0 = args[i].lower()
            a1 = args[i + 1]
            if a0 == "-n" or a0 == "--sectionalign":
                if a1 == "0":
                    al = get_alignment_from_file(msgs, names[-1])
                    if al is None:
                        msgs.error(1003, "Fail to get Alignment from %s", names[-1])
                        return finish()
                    if al < 0x400:
                        txt = c_format("%d", al)
                    elif al >= 0x100000:
                        txt = c_format("%dM", al // 0x100000)
                    else:
                        txt = c_format("%dK", al // 0x400)
                    value = _ALIGN_LOOKUP.get(txt.lower())
                else:
                    value = _ALIGN_LOOKUP.get(a1.lower()) if a1 is not None else None
                if value is None:
                    msgs.error(1003, "Invalid option value", "%s = %s", args[i], a1)
                    return finish()
                aligns[-1] = value
                argc -= 2
                i += 2
            continue

        if a0 == "-n" or a0 == "--sectionalign":
            msgs.error(1000, "Unknown option",
                       "SectionAlign option must be specified with section file.")
            return finish()

        if a0 == "-v" or a0 == "--verbose":
            msgs.level = VERBOSE_LOG_LEVEL
            msgs.verbose("Verbose output Mode Set!")
            argc -= 1
            i += 1
            continue

        if a0 == "-q" or a0 == "--quiet":
            msgs.level = KEY_LOG_LEVEL
            msgs.key("Quiet output Mode Set!")
            argc -= 1
            i += 1
            continue

        if a0 == "-d" or a0 == "--debug":
            lvl = ascii_string_to_uint64(a1)
            if lvl is None:
                msgs.error(1003, "Invalid option value", "%s = %s", args[i], a1)
                return finish()
            if lvl > 9:
                msgs.error(1003, "Invalid option value",
                           "Debug Level range is 0-9, current input level is %d", lvl & U32)
                return finish()
            msgs.level = lvl
            msgs.debug(9, "Debug Mode Set", "Debug Output Mode Level %s is set!", a1)
            argc -= 2
            i += 2
            continue

        msgs.error(1000, "Unknown option", "%s", args[i])
        return finish()

    msgs.verbose("%s tool start.", UTILITY_NAME)

    if ffs_type == EFI_FV_FILETYPE_ALL:
        msgs.error(1001, "Missing option", "filetype")
        return finish()
    if guid == bytes(16):
        msgs.error(1001, "Missing option", "fileguid")
        return finish()
    if not names:
        msgs.error(1001, "Missing option", "Input files")
        return finish()

    verbose = VERBOSE_LOG_LEVEL >= msgs.level
    if verbose:
        msgs.verbose("Fv File type is %s", M_FFS_FILE_TYPE[ffs_type])
        msgs.verbose("Output file name is %s", out_name)
        msgs.verbose("FFS File Guid is %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                     int.from_bytes(guid[0:4], "little"), int.from_bytes(guid[4:6], "little"),
                     int.from_bytes(guid[6:8], "little"), *guid[8:16])
        if ffs_attrib & FFS_ATTRIB_FIXED:
            msgs.verbose("FFS File has the fixed file attribute")
        if ffs_attrib & FFS_ATTRIB_CHECKSUM:
            msgs.verbose("FFS File requires the checksum of the whole file")
        msgs.verbose("FFS file alignment is %s", M_FFS_VALID_ALIGN_NAME[ffs_align])
    for k in range(len(names)):
        if aligns[k] == 0:
            aligns[k] = 1
        if verbose:
            msgs.verbose("the %dth input section name is %s and section alignment is %u",
                         k, names[k], aligns[k])

    buf = None
    pe_num = 0
    status, file_size, max_align, pe_num = get_section_contents(
        msgs, names, aligns, ffs_attrib, None, 0, pe_num)

    if ffs_type in (EFI_FV_FILETYPE_SECURITY_CORE, EFI_FV_FILETYPE_PEI_CORE,
                    EFI_FV_FILETYPE_DXE_CORE) and pe_num != 1:
        msgs.error(2000, "Invalid parameter",
                   "Fv File type %s must have one and only one Pe or Te section, "
                   "but %u Pe/Te section are input", M_FFS_FILE_TYPE[ffs_type], pe_num)
        return finish()
    if ffs_type in (EFI_FV_FILETYPE_PEIM, EFI_FV_FILETYPE_DRIVER,
                    EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER,
                    EFI_FV_FILETYPE_APPLICATION) and pe_num < 1:
        msgs.error(2000, "Invalid parameter",
                   "Fv File type %s must have at least one Pe or Te section, "
                   "but no Pe/Te section is input", M_FFS_FILE_TYPE[ffs_type])
        return finish()

    if status == EFI_BUFFER_TOO_SMALL:
        buf = bytearray(file_size)
        status, file_size, max_align, pe_num = get_section_contents(
            msgs, names, aligns, ffs_attrib, buf, file_size, pe_num)
    if status != EFI_SUCCESS:
        return finish()

    msgs.verbose("the max alignment of all input sections is %u", max_align)
    idx = 0
    while idx < len(M_FFS_VALID_ALIGN) - 1:
        if M_FFS_VALID_ALIGN[idx] < max_align <= M_FFS_VALID_ALIGN[idx + 1]:
            break
        idx += 1
    if ffs_align < idx:
        ffs_align = idx
    msgs.verbose("the alignment of the generated FFS file is %u",
                 M_FFS_VALID_ALIGN[ffs_align + 1] if ffs_align + 1 < len(M_FFS_VALID_ALIGN) else 0)

    hdr = bytearray(SIZEOF_FFS_HEADER2)
    hdr[0:16] = guid
    hdr[18] = ffs_type
    if file_size + SIZEOF_FFS_HEADER >= MAX_FFS_SIZE:
        hsize = SIZEOF_FFS_HEADER2
        file_size = (file_size + SIZEOF_FFS_HEADER2) & U32
        hdr[24:32] = file_size.to_bytes(8, "little")
        ffs_attrib |= FFS_ATTRIB_LARGE_FILE
    else:
        hsize = SIZEOF_FFS_HEADER
        file_size = (file_size + SIZEOF_FFS_HEADER) & U32
        hdr[20:23] = (file_size & 0xFFFFFF).to_bytes(3, "little")
    msgs.verbose("the size of the generated FFS file is %u bytes", file_size)

    if ffs_align < 8:
        hdr[19] = (ffs_attrib | (ffs_align << 3)) & 0xFF
    else:
        hdr[19] = (ffs_attrib | ((ffs_align & 7) << 3) | FFS_ATTRIB_DATA_ALIGNMENT2) & 0xFF

    hdr[16] = (0x100 - (sum(hdr[:hsize]) & 0xFF)) & 0xFF
    if hdr[19] & FFS_ATTRIB_CHECKSUM:
        hdr[17] = _checksum8(buf) if buf is not None else 0
    else:
        hdr[17] = FFS_FIXED_CHECKSUM
    hdr[23] = FFS_STATE

    if out_name is not None:
        try:
            _os.remove(out_name)
        except (OSError, ValueError):
            pass
        try:
            fo = open(out_name, "wb", buffering=0)
        except OSError:
            msgs.error(1, "Error opening file", out_name)
            return finish()
        with fo:
            fo.write(memoryview(hdr)[:hsize])
            if buf is not None:
                mv = memoryview(buf)[:file_size - hsize]
                done = 0
                while done < len(mv):
                    done += fo.write(mv[done:])

    return finish()
'''


def _load_core():
    try:
        import posix as os_
    except ImportError:          # Windows
        import nt as os_
    path = __file__
    folder, _, base = path.replace("\\", "/").rpartition("/")
    cache_dir = (folder or ".") + "/__pycache__"
    cache = "%s/%s.core-%x.bin" % (cache_dir, base.rpartition(".")[0] or base, sys.hexversion)
    try:
        st = os_.stat(path)
        key = ("GFFS:%x:%d:%d\n" % (sys.hexversion, st.st_mtime_ns, st.st_size)).encode()
    except (OSError, ValueError):
        key = None
    if key is not None:
        try:
            with open(cache, "rb") as f:
                blob = f.read()
            if blob.startswith(key):
                return marshal.loads(blob[len(key):])
        except (OSError, ValueError, EOFError, TypeError):
            pass
    code = compile("\n" * (_CORE_LINE - 1) + _CORE, path, "exec")
    if key is not None:
        tmp = "%s.%d.tmp" % (cache, os_.getpid())
        try:
            try:
                os_.mkdir(cache_dir)
            except OSError:
                pass
            with open(tmp, "wb") as f:
                f.write(key + marshal.dumps(code))
            os_.replace(tmp, cache)
        except OSError:
            try:
                os_.remove(tmp)
            except OSError:
                pass
    return code


exec(_load_core(), globals())
del _CORE, _load_core

if __name__ == "__main__":
    sys.exit(main())
