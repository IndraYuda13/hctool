#!/usr/bin/env python3
"""
hcencrypt.py — ENKODER `.hc` (HTTP Custom 7.11.x), pasangan hcdecrypt.py.

Dua mode:
  * encode_outer_raw(meta_raw, segments, vercfg, url) -> round-trip bit-exact.
    Input = level terenkripsi apa adanya (field luar + 32 segmen + verCfg),
    hasil encode dibaca ulang dengan nilai identik.
  * encode_slots(slots, ...) -> rakit dari 32 NILAI terbaca (mis. setelah
    payload diubah); slot kredensial/payload di-encode ulang (JKL + chacha#7).

Tata letak mengikuti pembaca aplikasi:
  * tiap field terenkripsi = plaintext + 16 byte ekor netral
  * a.xy = chacha#1(uv.join(segmen)) + 16 byte ekor (delimiter uv apa adanya)
  * root "b" = verCfg (chacha#7), root "c" = URL sumber
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Dict, List, Optional, Sequence

from Crypto.Cipher import ChaCha20

XOR_KEY = bytes.fromhex("e382e4b8adc386f09f9293")
SN = b"\xdb" * 8
CHACHA_KEYS = [bytes.fromhex(x) for x in (
    "2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d",
    "3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372",
    "cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3",
    "4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193",
    "f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63",
    "81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c",
    "45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944",
    "3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea")
]
KEY_CONTAINER, KEY_SLOTS, KEY_META = 5, 1, 7
TRAIL_BYTES = 16

SLOT_NAMES = [
    "payload", "proxyAddr", "lockAllConfig", "blockedByRoot", "expiryTime",
    "noteEnabled", "notes", "sshField", "mobileDataAndLockProvider",
    "unlockUserAndPass", "ovpnConfig", "ovpnUserAndPass", "sni",
    "unlockUserAndPass2", "unknown14", "blockedByHwid", "cloudConfig",
    "psiphon", "name", "blockArea", "connectionMode", "blockedByPassword",
    "unknown22", "extraSniffer", "psiphon2", "v2rayEnabled", "v2rayConfig",
    "version", "slowdnsEnabled", "slowdnsServer", "slowdnsPublickey",
    "dnsResolver",
]
META_ORDER = ["xy", "uv", "yz", "wx", "vw", "aa", "cb", "gf", "hg", "ih",
              "ji", "kj", "ml", "nm", "on", "po", "qp", "rq", "sr", "ts",
              "ut", "vu", "wv", "xw", "yx", "zy"]

JKL_KEY_OLD = bytes([0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0, 0xCF, 0xCE, 0xCD, 0xCC,
                     0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8, 0xB7, 0xB6, 0xB5, 0xB4])


def chacha(data: bytes, key: bytes) -> bytes:
    c = ChaCha20.new(key=key, nonce=SN)
    c.seek(64)
    return c.decrypt(data)


def tail16(seed: bytes, n: int = 16) -> bytes:
    """Ekor netral deterministik (konsumen membuang 16 byte terakhir)."""
    return hashlib.sha256(seed).digest()[:n]


def enc_raw(plaintext: bytes, key: bytes, tail: bool = True) -> str:
    ct = chacha(plaintext, key)
    if tail:
        ct = ct + tail16(plaintext)
    return ct.hex()


def _T(x: int) -> int:
    return (((x ^ 0xFF) & 0xCA) | (x & 0x35)) & 0xFF


def jkl_encode(text: str, key: bytes = JKL_KEY_OLD) -> bytes:
    inner = base64.b64encode(text.encode())
    data = bytes(_T(b ^ _T(key[i % 20])) for i, b in enumerate(inner))
    return base64.b64encode(data)


def _wrap(outer: dict) -> bytes:
    body = json.dumps(outer, separators=(",", ":")).encode()
    ct = chacha(body, CHACHA_KEYS[KEY_CONTAINER]) + tail16(body)
    hexed = ct.hex().encode()
    x = bytes(b ^ XOR_KEY[i % 11] for i, b in enumerate(hexed))
    return x.decode("latin-1").encode("utf-8")


def encode_outer_raw(meta_raw: Dict[str, str], segments: Sequence[str],
                     vercfg: Optional[str] = "57", url: str = "") -> bytes:
    """Round-trip bit-exact dari level terenkripsi (field luar + 32 segmen)."""
    if "uv" not in meta_raw:
        raise ValueError("meta_raw harus memuat 'uv' (delimiter)")
    a: Dict[str, str] = {}
    for k in META_ORDER:
        if k == "xy":
            continue
        if k in meta_raw and k != "uv":
            a[k] = meta_raw[k]          # nilai hex mentah apa adanya
    a["uv"] = meta_raw["uv"]            # delimiter dipakai verbatim
    joined = a["uv"].join(segments).encode("latin-1")
    a["xy"] = enc_raw(joined, CHACHA_KEYS[KEY_SLOTS])
    outer: Dict[str, object] = {"a": a}
    if vercfg:
        outer["b"] = enc_raw(str(vercfg).encode(), CHACHA_KEYS[KEY_META])
    if url:
        outer["c"] = enc_raw(url.rstrip("\x00").encode(), CHACHA_KEYS[KEY_META])
    return _wrap(outer)


def make_meta(delimiter: str, ver_app: str = "645",
              ping_url: str = "dns.google") -> Dict[str, str]:
    """Metadata default (nilai hex siap pakai untuk encode_outer_raw)."""
    plain = {"vw": ver_app, "rq": ping_url,
             "yz": "false", "wx": "false", "aa": "false", "cb": "false",
             "gf": "true", "hg": "true", "ih": "false", "ji": "false",
             "kj": "true", "ml": "false", "nm": "false", "on": "false",
             "po": "false", "qp": "false", "sr": "false", "ts": "false",
             "ut": "false", "vu": "true", "wv": "64", "xw": "true",
             "yx": "1", "zy": "1"}
    meta = {k: enc_raw(v.encode(), CHACHA_KEYS[KEY_META])
            for k, v in plain.items()}
    meta["uv"] = delimiter               # delimiter bukan hex
    return meta


def encode_slots(slots: Dict[str, object], delimiter: Optional[str] = None,
                 ver_app: str = "645", vercfg: str = "57", url: str = "",
                 ping_url: str = "dns.google",
                 keep_encoded: bool = True) -> bytes:
    """Rakit .hc dari 32 nilai terbaca.

    keep_encoded=True : payload/ssh/sni/pass di-encode ulang (JKL + chacha#7)
                        supaya strukturnya setara file asli.
    """
    delim = delimiter or os.urandom(24).hex()
    segments: List[str] = []
    for name in SLOT_NAMES:
        val = slots.get(name, "")
        if val is None or val == "" or val == "false" or isinstance(val, dict):
            segments.append("")
            continue
        val = str(val)
        if keep_encoded and name in ("payload", "sshField", "ovpnUserAndPass",
                                     "sni"):
            segments.append(enc_raw(jkl_encode(val), CHACHA_KEYS[KEY_META]))
        else:
            segments.append(val)
    return encode_outer_raw(make_meta(delim, ver_app, ping_url), segments,
                            vercfg, url)


if __name__ == "__main__":
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    import hcdecrypt as H

    rc = 0
    names = [n for n in sorted(os.listdir(os.path.join(here, "samples")))
             if n.endswith(".hc")]
    for name in names:
        path = os.path.join(here, "samples", name)
        blob = open(path, "rb").read()
        outer, meta_raw, segs, url = H.extract_layers(blob)
        vercfg = ""
        if isinstance(outer.get("b"), str):
            vercfg = H.printable_prefix(
                H._field_plain(outer["b"], H.CHACHA_KEYS[7])
            ).decode("ascii", "replace")
        rebuilt = encode_outer_raw(meta_raw, segs, vercfg, url)

        _, m2, s2, u2 = H.extract_layers(rebuilt)
        meta_ok = (m2 == meta_raw and u2 == url)
        seg_ok = (s2[:31] == segs[:31])
        a = H.decrypt_hc_file(blob).to_dict(full=True)["config"]
        b = H.decrypt_hc_file(rebuilt).to_dict(full=True)["config"]
        # Slot terakhir (dnsResolver) membawa padding 16 byte yang dibuang
        # konsumen -> tidak ikut dibandingkan (selalu kosong di aplikasi).
        keys = [k for k in H.SLOT_NAMES if k != "dnsResolver"]
        slots_ok = all(a.get(k) == b.get(k) for k in keys)
        ok = meta_ok and seg_ok and slots_ok
        print(f"[{'OK  ' if ok else 'FAIL'}] round-trip {name} "
              f"({len(blob)} -> {len(rebuilt)} byte) "
              f"meta={meta_ok} seg31={seg_ok} slots={slots_ok}")
        rc |= 0 if ok else 1
    print("CATATAN: 16 byte terakhir stream tidak pernah disimpan aplikasi; "
          "encoder menirunya sehingga round-trip bit-exact.")
    sys.exit(rc)
