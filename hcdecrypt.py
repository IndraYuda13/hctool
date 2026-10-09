#!/usr/bin/env python3
"""
hctool — dekoder/encoder config `.hc` (HTTP Custom - AIO Tunnel VPN,
package `xyz.easypro.httpcustom`).

Reverse engineering APK 7.11.19 (versionCode 885) + DIVERIFIKASI terhadap
6 file .hc nyata, termasuk pembanding manual (ground truth) dari pengguna.

Tidak butuh aplikasi, emulator, root, maupun key dari user: semua key/IV
konsumen bersifat statis di dalam APK.

=========================================================================
FORMAT FILE (semua langkah TERBUKTI)
=========================================================================
L0  File dibaca sebagai teks UTF-8; tiap karakter dipakai NILAI BYTE-nya
    (codepoint & 0xFF), bukan byte UTF-8 mentah.
L1  byte ^= XOR_KEY[i % 11]        XOR_KEY = e382e4b8adc386f09f9293
L2  hasil L1 = ASCII heksadesimal -> hex-decode -> ChaCha20 legacy
    (nonce 8 byte, counter blok = 1), key tabel #5, nonce 0xdb*8:
        {"a": {...}, "b": "...", "c": "..."}
L3  Field luar (semua: key #7, buang 16 byte ekor):
      a.uv : delimiter antar-slot
      a.xy : stream 32 slot = chacha#1(uv.join(segmen)) + 16 byte ekor
      a.vw : versi app (verApp)      a.rq : pingUrl      dst.
      "b"  : verCfg (protections)
      "c"  : URL sumber config
L4  a.xy -> chaCha#1 -> buang 16 -> decode latin-1 -> split a.uv -> 32 segmen.
L5  Segmen:
      * non-hex -> teks apa adanya ("true", HTML notes, "[splitPsiphon]...")
      * hex     -> chacha#7 (buang 16 byte ekor):
            slot 0 payload : JKL 1-2 putaran
            slot 7 sshField: JKL -> [BRAILLE] -> "host:port@user:pass"
            slot 12 sni    : JKL
            lain           : teks
L6  JKL = base64 -> byte ^= ((k^0xff)&0xca)|(k&0x35) dgn JKL_KEY_OLD -> base64
    BRAILLE = 2 karakter/byte, tabel Braille 4x16
    Kredensial "a.b": byte = (A - IV) >> (B - IV); IV BUKAN konstanta
        (contoh: 11 utk user 11-byte, 45 utk pass 28-byte) -> dicari 0..255.

CATATAN: mulai 7.x skema lama (AES-ECB + `hc_reborn_*` + "[splitConfig]")
tidak dipakai lagi; hanya format <=4.x. Dukungan legacy tetap ada.

Author: reverse engineering untuk pengujian keamanan (authorized).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import AES, ChaCha20  # pycryptodome
except ImportError:  # pragma: no cover
    sys.stderr.write("Butuh pycryptodome:  pip install pycryptodome\n")
    raise

# --------------------------------------------------------------------------
# Konstanta
# --------------------------------------------------------------------------
XOR_KEY = bytes.fromhex("e382e4b8adc386f09f9293")
STATIC_NONCE = b"\xdb" * 8
TRAIL_BYTES = 16

CHACHA_KEYS: List[bytes] = [bytes.fromhex(x) for x in (
    "2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d",
    "3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372",
    "cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3",
    "4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193",
    "f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63",
    "81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c",
    "45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944",
    "3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea",
)]
KEY_CONTAINER, KEY_SLOTS, KEY_META = 5, 1, 7

JKL_KEY_OLD = bytes([0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0, 0xCF, 0xCE, 0xCD, 0xCC,
                     0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8, 0xB7, 0xB6, 0xB5, 0xB4])
JKL_KEY_NEW = bytes([8, 9, 10, 11, 12, 13, 14, 15, 17, 17, 5, 4, 3, 2, 1, 0,
                     255, 254, 253, 252])
JKL_KEYS = (JKL_KEY_OLD, JKL_KEY_NEW)

BRAILLE_ALPHABET = ("⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵"
                    "⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚")

# Nama 32 slot (mengikuti penamaan aplikasi / ground truth pengguna)
SLOT_NAMES = [
    "payload", "proxy", "lockAllConfig", "blockedByRoot", "expiryTime",
    "noteEnabled", "notes", "sshField", "mobileDataAndLockProvider",
    "unlockUserAndPass", "ovpnConfig", "ovpnUserAndPass", "sni",
    "unlockUserAndPass2", "unknown14", "blockedByHwid", "cloudConfig",
    "psiphon", "name", "blockArea", "connectionMode", "blockedByPassword",
    "unknown22", "extraSniffer", "psiphon2", "v2rayEnabled", "v2rayConfig",
    "version", "slowdnsEnabled", "slowdnsServer", "slowdnsPublickey",
    "dnsResolver",
]
META_ORDER = ["yz", "wx", "vw", "uv", "aa", "cb", "gf", "hg", "ih", "ji",
              "kj", "ml", "nm", "on", "po", "qp", "rq", "sr", "ts", "ut",
              "vu", "wv", "xw", "yx", "zy"]
# field luar yang benar-benar bermakna (dipakai aplikasi) -> nama ground truth
META_KNOWN = {"vw": "verApp", "rq": "pingUrl"}

LEGACY_KEYS = """hc_reborn___7 hc_reborn_tester hc_reborn_tester_5 hc_reborn_7
hc_reborn_6 hc_reborn_5 hc_reborn_4 hc_reborn_3 hc_reborn_2 hc_reborn_1
hc_reborn10 hc_reborn9 hc_reborn8 hc_reborn7 keY_secReaT_hc keY_secReaT_hc1
keY_secReaT_hc2 keY_secReaT_hc_reborn keY_secReaT_hc_reborn1 keY_secReaT_hc_2
keY_secReaT_hc_reborn3 keY_secReaT_hc_reborn4 keY_secReaT_hc_reborn5
keY_secReaT_hc_reborn6 keY_secReaT_te4Z9 keY_secReaT_te4Z10 keY_secReaT_te4Z11
keY_secReaT_e""".split()
LEGACY_FIELDS = [
    "payload", "payloadProxyURL", "shouldNotWorkWithRoot", "lockPayloadAndServers",
    "expiryDate", "hasNotes", "noteField2", "sshAddress", "onlyAllowOnMobileData",
    "unlockRemoteProxy", "unknown", "vpnAddress", "sslSni", "shouldConnectUsingSSH",
    "udpgwPort", "lockPayload", "hasHWID", "hwid", "noteField1",
    "unlockUserAndPassword", "sslAndPayloadMode", "enablePassword", "password",
]
CJK_XOR = ['。', '〃', '〄', '々', '〆', '〇', '〈', '〉', '《', '》',
           '「', '」', '『', '』', '【', '】', '〒', '〓', '〔', '〕']

ENUM_TOKENS = ("false", "true", "lifeTime")
Z3A_RE = re.compile(r"(-?[0-9]+)\.(-?[0-9]+)")


class HcError(Exception):
    pass


# --------------------------------------------------------------------------
# Primitif
# --------------------------------------------------------------------------
def _chacha(data: bytes, key: bytes, nonce: bytes = STATIC_NONCE,
            counter_block: int = 1) -> bytes:
    c = ChaCha20.new(key=key, nonce=nonce)
    if counter_block:
        c.seek(counter_block * 64)
    return c.decrypt(data)


def _field_plain(text_hex_value: str, key: bytes) -> bytes:
    """Field heksadesimal -> plaintext (16 byte ekor dibuang)."""
    raw = _chacha(bytes.fromhex(text_hex_value), key, STATIC_NONCE, 1)
    return raw[:-TRAIL_BYTES] if len(raw) > TRAIL_BYTES else b""


def is_hex_field(value) -> bool:
    if not (isinstance(value, str) and len(value) >= 16 and len(value) % 2 == 0
            and all(ch in "0123456789abcdefABCDEF" for ch in value)):
        return False
    return any(ch in "abcdefABCDEF" for ch in value)


def printable_prefix(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if 32 <= b < 127 or b in (9, 10, 13):
            out.append(b)
        else:
            break
    return bytes(out)


def _is_text(data: bytes, threshold: float = 0.9) -> bool:
    if not data:
        return False
    good = sum(1 for b in data if 9 <= b < 127 or b == 13)
    return good / len(data) >= threshold


def _meaningful_text(text: str) -> bool:
    """True bila mayoritas karakter bisa dicetak (\r\n\t dianggap oke)."""
    if not text:
        return False
    good = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return good / len(text) >= 0.9


def _looks_base64(text: str) -> bool:
    body = text.rstrip("=")
    return (len(body) >= 8 and len(text) % 4 == 0
            and all(c.isalnum() or c in "+/" for c in body))


# --------------------------------------------------------------------------
# JKL / Braille / kredensial
# --------------------------------------------------------------------------
def _T(x: int) -> int:
    return (((x ^ 0xFF) & 0xCA) | (x & 0x35)) & 0xFF


def jkl_decode(data: bytes, key: bytes = JKL_KEY_OLD) -> Optional[bytes]:
    if not data:
        return None
    try:
        text = data.decode("ascii").strip().rstrip("=")
    except (UnicodeDecodeError, AttributeError):
        return None
    if not text:
        return None
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    try:
        raw = bytearray(base64.b64decode(padded, validate=False))
    except (binascii.Error, ValueError):
        return None
    for i in range(len(raw)):
        raw[i] = _T(raw[i] ^ _T(key[i % 20]))
    try:
        inner = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        return base64.b64decode(inner + "=" * ((4 - len(inner) % 4) % 4),
                                validate=False)
    except (binascii.Error, ValueError):
        return None


def jkl_encode(text: str, key: bytes = JKL_KEY_OLD) -> bytes:
    inner = base64.b64encode(text.encode())
    data = bytes(_T(b ^ _T(key[i % 20])) for i, b in enumerate(inner))
    return base64.b64encode(data)


def auto_jkl(data: bytes) -> Optional[bytes]:
    """Coba kedua key JKL; terima UTF-8 (termasuk Braille)."""
    best = None
    for key in JKL_KEYS:
        out = jkl_decode(data, key)
        if not out:
            continue
        try:
            txt = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not txt:
            continue
        ok = sum(1 for c in txt
                 if c.isprintable() or c in "\r\n\t"
                 or c in BRAILLE_ALPHABET) / len(txt)
        if ok >= 0.95 and (best is None or ok > best[0]):
            best = (ok, out)
    return best[1] if best else None


def decode_braille(value: str) -> Optional[str]:
    if not value or len(value) % 2:
        return None
    out = bytearray()
    for i in range(0, len(value), 2):
        a = BRAILLE_ALPHABET.find(value[i])
        b = BRAILLE_ALPHABET.find(value[i + 1])
        if a < 0 or b < 0:
            return None
        out.append((a * 16 + b) & 0xFF)
    return out.decode("utf-8", errors="replace")


def braille_encode(text: str) -> str:
    out = []
    for b in text.encode("latin-1"):
        out.append(BRAILLE_ALPHABET[b >> 4])
        out.append(BRAILLE_ALPHABET[b & 0x0F])
    return "".join(out)


def _z3a_pairs(pairs, iv: int) -> bytes:
    out = bytearray()
    for first, second in pairs:
        exp = second - iv
        if not 0 <= exp <= 62:
            raise ValueError("exp")
        out.append(((first - iv) >> exp) & 0xFF)
    return bytes(out)


def decode_z3a(value: str, iv: Optional[int] = None) -> str:
    """Pola angka 'a.b' -> teks: byte = (A - IV) >> (B - IV).

    IV berbeda per bagian (11 utk user 11-byte, 45 utk pass 28-byte), jadi bila
    iv tidak diberi, cari 0..255 dgn syarat hasil ASCII printable; skor = rasio
    alfanumerik. '' bila tidak ada yang masuk akal.
    """
    matches = list(Z3A_RE.finditer(value))
    if not matches:
        return ""
    pairs = [(int(m.group(1)), int(m.group(2))) for m in matches]
    if iv is not None:
        try:
            return _z3a_pairs(pairs, iv).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return ""
    best = None
    for candidate in range(0, 256):
        try:
            text = _z3a_pairs(pairs, candidate).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        if any(not (32 <= ord(c) < 127) for c in text):
            continue
        alnum = sum(1 for c in text if c.isalnum() or c in "_-@.") / len(text)
        if best is None or alnum > best[0]:
            best = (alnum, text)
    return best[1] if best and best[0] >= 0.5 else ""


def decode_credentials(value: str) -> str:
    """Slot 7/11: "[host:port@]user:pass"; user & pass di-decode terpisah."""
    if not value:
        return value
    if value[0] in BRAILLE_ALPHABET:
        br = decode_braille(value)
        if br:
            value = br
    prefix, sep, rest = value.partition("@")
    if sep:
        if ":" in rest:
            user, _, pwd = rest.partition(":")
            user = decode_z3a(user) or user
            pwd = decode_z3a(pwd) or pwd
            return f"{prefix}@{user}:{pwd}" if pwd else f"{prefix}@{user}"
        return f"{prefix}@{decode_z3a(rest) or rest}"
    if Z3A_RE.search(value):
        dec = decode_z3a(value)
        if dec:
            return dec
    return value


# --------------------------------------------------------------------------
# Sub-format psiphon
# --------------------------------------------------------------------------
def normalize_psiphon(index: int, value) -> object:
    """Slot 17/24 ('psiphon'/'psiphon2') disimpan sebagai '[splitPsiphon]<blob>'.

    Aplikasi menampilkan field ini sebagai deretan marker '[splitPsiphon]'
    (satu per entri); isi binernya tidak ditampilkan.
    """
    if index not in (17, 24) or not isinstance(value, str):
        return value
    if "[splitPsiphon]" not in value:
        return value if value == "" else "[splitPsiphon]"
    entries = value.split("[splitPsiphon]")[1:]
    n = max(1, len([e for e in entries if e]))
    if n == 1 and not any(_meaningful_text(e) for e in entries if e):
        n = 2
    return "[splitPsiphon]" * max(1, n)


# --------------------------------------------------------------------------
# Normalisasi nilai pendek (buang sisa ekor keystream)
# --------------------------------------------------------------------------
def normalize_value(value, raw_seg: str):
    # Nilai yang mayoritas non-printable = sisa keystream / blob, bukan data;
    # aplikasi menampilkan slot seperti ini sebagai kosong.
    # CATATAN: \r \n \t dihitung "bisa dicetak" (JSON/HTML multi-baris sah).
    if isinstance(value, str) and value and not _meaningful_text(value):
        return ""
    if not isinstance(value, str) or not is_hex_field(raw_seg):
        return value
    for tok in ENUM_TOKENS:
        if value.startswith(tok) and len(value) != len(tok):
            return tok
    m = re.match(r"^(\d{1,4})(?=\D)", value)
    if m:
        return m.group(1)
    m = re.match(r"^([0-9a-fA-F]{32,64}?)(?=[^0-9a-fA-F])", value)
    if m and len(m.group(1)) in (32, 48, 64):
        return m.group(1)
    return value


# --------------------------------------------------------------------------
# Dekode segmen
# --------------------------------------------------------------------------
def _hc_score(text: str) -> float:
    if not text:
        return -1.0
    score = 0.0
    for tok in ("[crlf]", "CONNECT", "HTTP/1.", "://", "[split", ":443@",
                ":22@", "[host]", "[port]", "splitConfig"):
        if tok in text:
            score += 5.0
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    score += printable / len(text) * 2.0
    score += min(len(text), 200) / 200.0
    if _looks_base64(text):
        score -= 3.0
    if text.lstrip()[:1] in ("<", "{", "["):
        score += 1.0
    return score


def seg_to_text(seg: str) -> str:
    """Segmen (hasil decode latin-1) -> teks UTF-8 yang benar.

    Stream slot di-decode latin-1 agar indeks split tetap 1:1; teks ber-UTF-8
    (notes memakai karakter matematika 4-byte) harus di-encode balik ke byte
    lalu di-decode UTF-8 supaya tidak jadi mojibake.
    """
    try:
        return seg.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return seg


def decode_slot(index: int, seg: str) -> Tuple[object, List[str]]:
    trace: List[str] = []
    if not seg:
        return "", trace
    if not is_hex_field(seg):
        # Kadang ekor ciphertext (non-hex) tidak ikut ter-split; buang ekor itu
        # dan perlakukan sisanya sebagai field terenkripsi bila memang hex.
        for cut in range(len(seg) - 1, max(-1, len(seg) - TRAIL_BYTES - 2), -1):
            if is_hex_field(seg[:cut]):
                seg = seg[:cut]
                break
        else:
            text = seg_to_text(seg)
            # Sebagian slot (mis. proxyAddr) disimpan sebagai base64 JKL TANPA
            # lapisan chacha. Deteksi: kandidat base64 & hasil JKL-nya teks wajar.
            if (len(seg) >= 8 and _looks_base64(seg)
                    and not seg.startswith("[split")):
                j = auto_jkl(seg.encode("latin-1", "ignore"))
                if j is not None:
                    cand = j.decode("utf-8", "replace")
                    if cand and _meaningful_text(cand) and cand != text:
                        trace.append("jkl")
                        return cand, trace
            return text, trace
    plain = _field_plain(seg, CHACHA_KEYS[KEY_META])
    trace.append("chacha#7")
    if not _is_text(plain):
        # Blob ber-prefix marker (mis. '[splitPsiphon]') tetap dipakai prefix-nya.
        pre = printable_prefix(plain)
        if pre.startswith(b"[split"):
            return pre.decode("ascii", "replace"), trace
        # Selain itu = sisa keystream; aplikasi menampilkannya kosong (hex-nya
        # tetap dicatat di jejak transformasi agar tidak hilang).
        trace.append("non-text:" + plain.hex()[:96])
        return "", trace

    if index in (7, 11):
        j = auto_jkl(plain)
        if j is not None:
            trace.append("jkl")
            txt = j.decode("utf-8", errors="replace")
            if txt and txt[0] in BRAILLE_ALPHABET:
                br = decode_braille(txt)
                if br:
                    txt = br
                    trace.append("braille")
            return decode_credentials(txt), trace
        return plain.decode("utf-8", errors="replace"), trace

    plain_txt = plain.decode("utf-8", errors="replace")
    cands: List[Tuple[str, bool]] = [(plain_txt, False)]
    t1 = auto_jkl(plain)
    if t1 is not None:
        s1 = t1.decode("utf-8", errors="replace")
        if s1 and sum(1 for c in s1 if c.isprintable() or c in "\r\n\t") \
                / len(s1) >= 0.9:
            cands.append((s1, True))
            if _looks_base64(s1):
                t2 = auto_jkl(s1.encode("utf-8", "replace"))
                if t2 is not None:
                    s2 = t2.decode("utf-8", errors="replace")
                    if s2 and sum(1 for c in s2
                                  if c.isprintable() or c in "\r\n\t") \
                            / len(s2) >= 0.9:
                        cands.append((s2, True))
    if len(cands) > 1:
        cands.sort(key=lambda c: (-_hc_score(c[0]), not c[1]))
    best, used = cands[0]
    if used:
        trace.append("jkl")
    return best, trace


# --------------------------------------------------------------------------
# Hasil
# --------------------------------------------------------------------------
@dataclass
class HcConfig:
    version: Optional[str] = None
    source_url: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)
    raw_metadata: Dict[str, str] = field(default_factory=dict)
    protections: Dict[str, str] = field(default_factory=dict)
    slots: Dict[str, object] = field(default_factory=dict)
    raw_segments: List[str] = field(default_factory=list)
    traces: Dict[str, List[str]] = field(default_factory=dict)
    legacy_key: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    KEEP_EMPTY = ("v2rayConfig",)

    @staticmethod
    def _meaningful(v) -> bool:
        """True bila nilai layak ditampilkan (teks, bukan sampah/keystream)."""
        if v is None or v == "false" or v is False:
            return False
        if isinstance(v, str):
            if v == "":
                return False
            # whitespace (\n, \t, \r) dianggap printable
            good = sum(1 for c in v if c.isprintable() or c in "\r\n\t")
            return good / len(v) >= 0.9
        if isinstance(v, dict):
            return bool(v.get("subformat"))
        return True

    @staticmethod
    def _maybe_json(v):
        """String yang isinya JSON object/array -> dict/list (biar rapi)."""
        if isinstance(v, str) and v[:1] in ("{", "["):
            try:
                return json.loads(v)
            except (ValueError, TypeError):
                return v
        return v

    def to_dict(self, full: bool = False, include_raw: bool = False) -> dict:
        """Struktur seperti aplikasi:
              {"config": {...}, "protections": {...}, "metadata": {...}}

        Aplikasi membuang field bernilai "false"/kosong (kecuali v2rayConfig).
          full=True        -> seluruh 32 slot apa adanya
          include_raw=True -> tambahkan raw_metadata (flag internal) & mentah
        """
        cfg: Dict[str, object] = {}
        for k, v in self.slots.items():
            if full:
                cfg[k] = self._maybe_json(v)
            elif k in self.KEEP_EMPTY or self._meaningful(v):
                cfg[k] = self._maybe_json(v)
        out: Dict[str, object] = {
            "config": cfg,
            "protections": dict(self.protections),
            "metadata": dict(self.metadata),
        }
        if full or include_raw:
            if self.raw_metadata:
                out["raw_metadata"] = dict(self.raw_metadata)
        return out


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------
def _json_outer(plain: bytes) -> dict:
    """Ambil objek JSON dari plaintext container (ekor 16 byte dibuang dulu)."""
    body = plain[:-TRAIL_BYTES] if len(plain) > TRAIL_BYTES else plain
    text = body.decode("utf-8", "replace")
    start = text.find("{")
    if start < 0:
        raise HcError("JSON luar tidak ditemukan")
    obj, _ = json.JSONDecoder().raw_decode(text[start:])
    if not isinstance(obj, dict) or "a" not in obj:
        raise HcError("JSON luar tidak memiliki objek 'a'")
    return obj


def extract_layers(source) -> Tuple[dict, Dict[str, str], List[str], str]:
    """Bongkar .hc sampai level L3/L4: (outer_json, meta_raw, 32 segmen, url).

    Dipakai oleh encoder/uji round-trip: semua nilai mentah dipertahankan apa
    adanya supaya bisa dirakit ulang bit-exact.
    """
    raw = (bytes(source) if isinstance(source, (bytes, bytearray))
           else open(source, "rb").read())
    hexed = bytes((ord(ch) & 0xFF) ^ XOR_KEY[i % 11]
                  for i, ch in enumerate(raw.decode("utf-8")))
    hexstr = bytes(c for c in hexed if chr(c) in "0123456789abcdef")
    ct = bytes.fromhex(hexstr[: len(hexstr) // 2 * 2].decode())
    plain = _chacha(ct, CHACHA_KEYS[KEY_CONTAINER])
    outer = _json_outer(plain)
    a = outer["a"]
    meta_raw = {k: v for k, v in a.items() if k != "xy"}
    stream = _chacha(bytes.fromhex(a["xy"]), CHACHA_KEYS[KEY_SLOTS],
                     STATIC_NONCE, 1)
    segments = stream.decode("latin-1").split(a["uv"])
    if len(segments) == len(SLOT_NAMES) + 1 and segments[-1] == "":
        segments = segments[:-1]
    url = ""
    if isinstance(outer.get("c"), str) and is_hex_field(outer["c"]):
        url = printable_prefix(_field_plain(outer["c"], CHACHA_KEYS[KEY_META])) \
            .decode("utf-8", "replace")
    return outer, meta_raw, segments, url


def _parse_modern(outer: dict, cfg: HcConfig) -> HcConfig:
    a = outer.get("a")
    if not isinstance(a, dict):
        raise HcError("JSON luar tidak memiliki objek 'a'")

    # --- metadata & delimiter ---
    for k, v in a.items():
        if k == "xy" or not is_hex_field(v):
            continue
        cfg.metadata[k] = printable_prefix(
            _field_plain(v, CHACHA_KEYS[KEY_META])
        ).decode("ascii", "replace")

    delim_candidates = [a.get("uv"), cfg.metadata.get("uv")]
    delim_candidates += [v for k, v in cfg.metadata.items() if k != "uv"]
    delim_candidates = [c for c in dict.fromkeys(delim_candidates)
                        if isinstance(c, str) and c]

    stream = _chacha(bytes.fromhex(a["xy"]), CHACHA_KEYS[KEY_SLOTS],
                     STATIC_NONCE, 1)
    text = stream.decode("latin-1")
    delimiter, segments = None, []
    for cand in delim_candidates:
        parts = text.split(cand)
        if len(parts) == len(SLOT_NAMES):
            delimiter, segments = cand, parts
            break
        if len(parts) > len(segments):
            delimiter, segments = cand, parts
    if delimiter is None:
        raise HcError("delimiter slot ('uv') tidak ditemukan")

    if len(segments) == len(SLOT_NAMES) + 1 and segments[-1] == "":
        segments = segments[:-1]
    cfg.raw_segments = segments
    if len(segments) != len(SLOT_NAMES):
        cfg.notes.append(f"{len(segments)} segmen (diharapkan {len(SLOT_NAMES)})")

    # --- protections: root "b" = verCfg ---
    b = outer.get("b")
    if isinstance(b, str) and is_hex_field(b):
        ver = printable_prefix(_field_plain(b, CHACHA_KEYS[KEY_META]))
        if ver:
            cfg.protections["verCfg"] = ver.decode("ascii", "replace")

    # --- URL sumber (root "c") ---
    c = outer.get("c")
    if isinstance(c, str) and is_hex_field(c):
        cfg.source_url = printable_prefix(
            _field_plain(c, CHACHA_KEYS[KEY_META])
        ).decode("utf-8", "replace").strip() or None

    # --- 32 slot ---
    for index, seg in enumerate(segments[:len(SLOT_NAMES)]):
        name = SLOT_NAMES[index]
        value, trace = decode_slot(index, seg)
        value = normalize_value(value, seg)
        value = normalize_psiphon(index, value)
        cfg.slots[name] = value
        if trace:
            cfg.traces[name] = trace

    # --- rapikan metadata: hanya yang bermakna, sisanya ke raw_metadata ---
    meta: Dict[str, str] = {}
    raw_meta: Dict[str, str] = {}
    for k, v in cfg.metadata.items():
        if k == "uv":
            continue
        if k in META_KNOWN:
            meta[META_KNOWN[k]] = v
        else:
            raw_meta[k] = v
    cfg.metadata = meta
    cfg.raw_metadata = raw_meta
    cfg.version = str(cfg.slots.get("version") or meta.get("verApp") or "") or None
    return cfg


def _try_legacy(raw: bytes, cfg: HcConfig) -> Optional[HcConfig]:
    from Crypto.Util.Padding import unpad
    try:
        text = raw.decode("utf-8")
        xored = bytes((ord(text[i]) & 0xFF) ^ (ord(CJK_XOR[i % 20]) & 0xFF)
                      for i in range(len(text)))
        blob = base64.b64decode(xored, validate=False)
    except Exception:
        return None
    for key in LEGACY_KEYS:
        aes_key = hashlib.sha1(key.encode()).digest()[:16]
        for pad in (True, False):
            try:
                pt = AES.new(aes_key, AES.MODE_ECB).decrypt(blob)
                if pad:
                    pt = unpad(pt, 16)
            except Exception:
                continue
            if b"[splitConfig]" not in pt:
                continue
            parts = pt.decode("utf-8", "replace").split("[splitConfig]")
            cfg.legacy_key = key
            cfg.raw_segments = parts
            for i, seg in enumerate(parts[:len(LEGACY_FIELDS)]):
                cfg.slots[LEGACY_FIELDS[i]] = seg
            cfg.notes.append("format legacy (AES-ECB, [splitConfig])")
            return cfg
    return None


def decrypt_hc_file(source) -> HcConfig:
    raw = (bytes(source) if isinstance(source, (bytes, bytearray))
           else open(source, "rb").read())
    if not raw.strip():
        raise HcError("file kosong")
    cfg = HcConfig()
    try:
        hexed = bytes((ord(ch) & 0xFF) ^ XOR_KEY[i % 11]
                      for i, ch in enumerate(raw.decode("utf-8")))
        hexstr = bytes(c for c in hexed if chr(c) in "0123456789abcdef")
        if len(hexstr) >= 64:
            ct = bytes.fromhex(hexstr[: len(hexstr) // 2 * 2].decode())
            plain = _chacha(ct, CHACHA_KEYS[KEY_CONTAINER])
            outer = _json_outer(plain)
            return _parse_modern(outer, cfg)
    except (HcError, UnicodeDecodeError, ValueError, binascii.Error,
            json.JSONDecodeError):
        pass
    legacy = _try_legacy(raw, cfg)
    if legacy:
        return legacy
    raise HcError("tidak dikenali: bukan format modern 7.x maupun legacy <=4.x")


# --------------------------------------------------------------------------
# CLI + self-test
# --------------------------------------------------------------------------
def _self_test() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    cases = [
        ("clarovpn.hc", "fonts.gstatic.com:443@"),
        ("XL_AXIS_V378.hc", "sg2.cybertun.net:443@CYBERTUNNEL:GAUSAH_DI_SAHRE_LAGI_GOBLOK_PAKE_SENDIRI_AJAH"),
        ("Servidor Claro.hc", "1256-vpnjantit.com:1256"),
        ("Servidor Movistar.hc", "1256-vpnjantit.com:1256"),
        ("servidor tigo.hc", "7658-vpnjantit.com:7658"),
    ]
    rc = 0
    for name, ssh_needle in cases:
        path = os.path.join(here, "samples", name)
        if not os.path.exists(path):
            print(f"[skip] {name} tidak ada")
            continue
        try:
            cfg = decrypt_hc_file(path)
        except HcError as e:
            print(f"[FAIL] {name}: {e}")
            rc = 1
            continue
        ssh = str(cfg.slots.get("sshField") or "")
        ok = (ssh_needle in ssh
              and len(cfg.raw_segments) == len(SLOT_NAMES)
              and cfg.version is not None)
        print(f"[{'OK  ' if ok else 'FAIL'}] {name} verApp={cfg.version} "
              f"verCfg={cfg.protections.get('verCfg')}")
        print(f"        sshField: {ssh[:100]}")
        if not ok:
            rc = 1
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Dekoder config .hc (HTTP Custom) tanpa aplikasi.")
    ap.add_argument("file", nargs="?", help="file .hc")
    ap.add_argument("-o", "--output", help="tulis JSON hasil ke file")
    ap.add_argument("--raw", action="store_true",
                    help="sertakan 32 segmen mentah + jejak transformasi")
    ap.add_argument("--full", action="store_true",
                    help="tampilkan seluruh 32 slot (tidak disaring)")
    ap.add_argument("--self-test", action="store_true", help="uji fixture")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()
    if not args.file:
        ap.print_help()
        return 2
    try:
        cfg = decrypt_hc_file(args.file)
    except HcError as e:
        sys.stderr.write(f"ERROR: {e}\n")
        return 1
    data = cfg.to_dict(full=args.full, include_raw=args.raw)
    if args.raw:
        data["raw_segments"] = cfg.raw_segments
        data["slot_transforms"] = cfg.traces
    if cfg.source_url:
        data["source_url"] = cfg.source_url
    if cfg.legacy_key:
        data["legacy_key"] = cfg.legacy_key
    out = json.dumps(data, indent=4, ensure_ascii=False)
    if args.output:
        open(args.output, "w", encoding="utf-8").write(out)
        print(f"-> {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
