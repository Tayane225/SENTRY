"""File type identification from magic bytes (content) and extension (claimed type)."""

from __future__ import annotations

import os

EXECUTABLE_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".drv", ".efi", ".msi", ".msp", ".mui",
    ".so", ".dylib", ".bin", ".elf", ".ko", ".appimage", ".run", ".out",
}
SCRIPT_EXTS = {
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sh",
    ".bash", ".zsh", ".ksh", ".py", ".pyw", ".pl", ".rb", ".php", ".phtml", ".asp", ".aspx", ".ashx", ".jsp",
    ".lua", ".applescript", ".scpt", ".reg", ".inf", ".command", ".mjs", ".cjs",
}
DOCUMENT_EXTS = {
    ".doc", ".docm", ".docx", ".dot", ".dotm", ".xls", ".xlsm", ".xlsx", ".xlsb", ".xlam", ".ppt", ".pptm",
    ".pptx", ".ppsm", ".rtf", ".pdf", ".one", ".odt", ".ods",
}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".cab", ".iso",
                ".img", ".vhd", ".vhdx", ".jar", ".apk", ".war", ".nupkg", ".whl"}
SHORTCUT_EXTS = {".lnk", ".url", ".desktop", ".webloc", ".settingcontent-ms"}
HTML_EXTS = {".html", ".htm", ".svg", ".xhtml", ".mht", ".mhtml"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff", ".heic"}
MEDIA_EXTS = {".mp3", ".mp4", ".mkv", ".avi", ".mov", ".wav", ".flac", ".ogg", ".m4a", ".wmv", ".webm"}

# documents whose genuine content has a known signature (used to spot encrypted/corrupted files)
EXPECTED_MAGIC = {
    ".pdf": "pdf", ".docx": "zip", ".xlsx": "zip", ".pptx": "zip", ".docm": "zip", ".xlsm": "zip",
    ".pptm": "zip", ".odt": "zip", ".ods": "zip", ".zip": "zip", ".doc": "ole", ".xls": "ole", ".ppt": "ole",
    ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".7z": "7z", ".rar": "rar",
}


def magic_kind(head: bytes) -> str:
    """Identify content from its first bytes. Returns a short magic label."""
    if not head:
        return "empty"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if head[:4] == b"\xca\xfe\xba\xbe":
        # Mach-O fat binary or Java class; fat binaries have a small arch count next
        return "macho" if int.from_bytes(head[4:8], "big") < 40 else "java_class"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"{\\rt"):
        return "rtf"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"MSCF"):
        return "cab"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"\x89PNG"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"GIF8"):
        return "gif"
    if head.startswith(b"#!"):
        return "script"
    lowered = head[:512].lower().lstrip()
    if lowered.startswith(b"<!doctype html") or lowered.startswith(b"<html") or b"<script" in lowered:
        return "html"
    if b"<?php" in lowered:
        return "script"
    if _looks_text(head):
        return "text"
    return "binary"


def _looks_text(head: bytes) -> bool:
    sample = head[:2048]
    if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return printable / max(1, len(sample)) > 0.95


def ext_of(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def kind_of(ext: str, magic: str) -> str:
    """Effective kind: content wins over extension for executables (a disguised PE is an executable)."""
    if magic in ("pe", "elf", "macho"):
        return "executable"
    if magic == "lnk" or ext in SHORTCUT_EXTS:
        return "shortcut"
    if magic in ("zip", "rar", "7z", "gzip", "bzip2", "xz", "tar", "cab"):
        if ext in DOCUMENT_EXTS:
            return "document"
        return "archive"
    if magic in ("ole", "pdf", "rtf") or ext in DOCUMENT_EXTS:
        return "document"
    if ext in EXECUTABLE_EXTS:
        return "executable"
    if ext in SCRIPT_EXTS or magic == "script":
        return "script"
    if ext in HTML_EXTS or magic == "html":
        return "html"
    if ext in ARCHIVE_EXTS:
        return "archive"
    if ext in IMAGE_EXTS or magic in ("png", "jpeg", "gif"):
        return "image"
    if ext in MEDIA_EXTS:
        return "media"
    if magic == "text":
        return "text"
    return "other"


INTERESTING_KINDS = {"executable", "script", "document", "archive", "shortcut", "html"}


def is_interesting(kind: str) -> bool:
    return kind in INTERESTING_KINDS
