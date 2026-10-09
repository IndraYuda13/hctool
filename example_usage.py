#!/usr/bin/env python3
"""
Contoh pemakaian hctool.

1) Decode sebuah .hc -> JSON (struktur seperti yang ditampilkan aplikasi)
2) Ubah payload-nya, tulis ulang jadi .hc baru yang valid.
"""
import json
import sys

import hcdecrypt as H
from hcencrypt import encode_outer_raw, enc_raw, jkl_encode

STORE = {
    "605": "cybertun",
    "607": "cybertun",
}


def main(path: str) -> int:
    blob = open(path, "rb").read()

    cfg = H.decrypt_hc_file(blob)
    print(json.dumps(cfg.to_dict(), indent=2, ensure_ascii=False))

    outer, meta_raw, segments, url = H.extract_layers(blob)
    vercfg = ""
    if isinstance(outer.get("b"), str):
        vercfg = H.printable_prefix(
            H._field_plain(outer["b"], H.CHACHA_KEYS[7])
        ).decode("ascii", "replace")

    segments = list(segments)
    segments[0] = enc_raw(
        jkl_encode("CONNECT [host_port] HTTP/1.1[crlf][crlf]"),
        H.CHACHA_KEYS[7],
    )
    out = encode_outer_raw(meta_raw, segments, vercfg, url)
    dst = path.rsplit(".", 1)[0] + ".patched.hc"
    open(dst, "wb").write(out)

    check = H.decrypt_hc_file(out)
    print("\n-- patched payload:", check.slots.get("payload"))
    print("-- written:", dst)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: example_usage.py <config.hc>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
