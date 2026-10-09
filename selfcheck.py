#!/usr/bin/env python3
"""
selfcheck.py — verifikasi dua arah hctool:

1) ROUND-TRIP (bit-per-bit): baca sampel nyata -> rakit ulang file HANYA dari
   level terenkripsi (field luar mentah + 32 segmen mentah) -> bandingkan
   lapisan L3 (field luar), L4 (32 segmen), L5 (tiap slot terdekripsi),
   dan field url. Harus identik.
2) FORWARD (dari nilai terbaca): encode_slots() -> hcdecrypt() -> nilai sama.
3) CAST/VARIANT: encode_outer_raw() dipakai untuk mengubah 1 slot lalu
   dipastikan slot itu berubah dan yang lain tidak.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from typing import Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import hcdecrypt as H          # noqa: E402
import hcencrypt as E          # noqa: E402
from Crypto.Cipher import ChaCha20  # noqa: E402


def layers(blob: bytes) -> Tuple[dict, dict, List[str], str]:
    """Bongkar file .hc jadi (outer_json, meta_raw, 32_segmen, url)."""
    hexed = H._deobfuscate_outer(blob)
    hx = bytes(c for c in hexed if chr(c) in "0123456789abcdef")
    ct = bytes.fromhex(hx[: len(hx) // 2 * 2].decode())
    plain = H._chacha(ct, H.CHACHA_KEYS[5])
    outer = json.loads(plain[: plain.rfind(b"}") + 1].decode("utf-8", "replace"))
    a = outer["a"]
    meta_raw = {k: v for k, v in a.items() if k != "xy"}
    stream = H._chacha(bytes.fromhex(a["xy"]), H.CHACHA_KEYS[1],
                       H.STATIC_NONCE, 1)[:-H.TRAIL_BYTES]
    segs = stream.decode("latin-1").split(meta_raw["uv"])
    url = ""
    if isinstance(outer.get("c"), str):
        url = H.printable_prefix(
            H._chacha_hex(outer["c"], H.CHACHA_KEYS[7], strip=0)
        ).decode("utf-8", "replace")
    return outer, meta_raw, segs, url


def roundtrip(path: str) -> bool:
    raw = open(path, "rb").read()
    cfg = H.decrypt_hc_file(raw)
    outer, meta_raw, segs, url = layers(raw)

    rebuilt = E.encode_outer_raw(meta_raw, segs, url)
    o2, m2, s2, u2 = layers(rebuilt)
    _ = (o2, u2)
    cfg2 = H.decrypt_hc_file(rebuilt)

    ok = True
    checks = [
        ("field luar", meta_raw == m2),
        ("32 segmen", segs == s2),
        ("slot terbaca",
         {k: cfg.slots.get(k) for k in H.SLOT_NAMES} ==
         {k: cfg2.slots.get(k) for k in H.SLOT_NAMES}),
    ]
    for name, same in checks:
        print(f"   [{'OK  ' if same else 'FAIL'}] {name}")
        ok = ok and same
    return ok


def forward(path: str) -> bool:
    """Nilai terbaca -> encode_slots -> baca lagi (harus sama)."""
    cfg = H.decrypt_hc_file(path)
    blob = E.encode_slots(cfg.slots, version=cfg.version or "645",
                          source_url=cfg.source_url or "",
                          delimiter=cfg.metadata.get("uv_raw"))
    cfg2 = H.decrypt_hc_file(blob)
    keys = [k for k in H.SLOT_NAMES
            if cfg.slots.get(k) not in ("", None, [])]
    diffs = [k for k in keys if str(cfg.slots.get(k)) != str(cfg2.slots.get(k))]
    print(f"   [{'OK  ' if not diffs else 'FAIL'}] slot identik: "
          f"{len(keys)-len(diffs)}/{len(keys)}")
    for k in diffs:
        print(f"        beda {k}: {str(cfg.slots.get(k))[:60]!r} != "
              f"{str(cfg2.slots.get(k))[:60]!r}")
    return not diffs


def mutate(path: str) -> bool:
    """Ubah payload via jalur mentah; pastikan hanya slot itu berubah."""
    raw = open(path, "rb").read()
    cfg_before = H.decrypt_hc_file(raw)
    outer, meta_raw, segs, url = layers(raw)
    new = list(segs)
    new[0] = E.field_hex(E.jkl_encode("CONNECT [host_port] HTTP/1.1[crlf][crlf]"),
                         H.CHACHA_KEYS[7], seed=b"connect-poc")
    blob = E.encode_outer_raw(meta_raw, new, "")
    after = H.decrypt_hc_file(blob)
    changed = str(after.slots.get("payload", ""))
    others = all(
        str(after.slots.get(k)) == str(cfg_before.slots.get(k))
        for k in H.SLOT_NAMES if k != "payload")
    good = "CONNECT" in changed and others
    print(f"   [{'OK  ' if good else 'FAIL'}] mutasi payload = {changed[:60]!r}"
          f" (slot lain utuh: {others})")
    return good


def main() -> int:
    samples = [f for f in sorted(os.listdir(os.path.join(HERE, "samples")))
               if f.endswith(".hc")]
    rc = 0
    for name in samples:
        p = os.path.join(HERE, "samples", name)
        print(f"== {name}")
        try:
            if not roundtrip(p):
                rc = 1
            if not forward(p):
                rc = 1
            if not mutate(p):
                rc = 1
        except Exception as e:
            print(f"   [FAIL] exception: {type(e).__name__}: {e}")
            rc = 1
    print("\nHASIL:", "SEMUA OK" if rc == 0 else "ADA YANG GAGAL")
    return rc


if __name__ == "__main__":
    sys.exit(main())
