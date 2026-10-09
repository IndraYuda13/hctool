# hctool — HTTP Custom `.hc` config decoder/encoder

Reverse-engineered decoder **and** encoder for `.hc` configuration files used by
**HTTP Custom – AIO Tunnel VPN** (`xyz.easypro.httpcustom`).

The format was recovered from APK **7.11.19 (versionCode 885, arm64-v8a)** and
verified against real-world `.hc` files. The tool opens "locked" configs
**without the app, without an emulator, without root, and without any key from
the user** — every key and IV the client uses is a static constant baked into
the APK.

```
$ python3 hcdecrypt.py config.hc
{
    "config": {
        "payload": "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: [host][crlf][crlf]GET-RAY / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]",
        "proxy": "www.example.com:80",
        "lockAllConfig": "true",
        "expiryTime": "lifeTime",
        "noteEnabled": "true",
        "notes": "Premium server list ...",
        "sshField": "uk.sshws.net:80@user:pass",
        "ovpnUserAndPass": ":",
        "unlockUserAndPass2": "true",
        "connectionMode": "1",
        "psiphon2": "[splitPsiphon][splitPsiphon]",
        "v2rayConfig": "",
        "version": "645"
    },
    "protections": { "verCfg": "57" },
    "metadata": { "verApp": "645", "pingUrl": "dns.google" }
}
```

Output is byte-for-byte equivalent to what the app itself shows (verified field
by field against app-produced ground truth).

---

## Features

* **Decoder** (`hcdecrypt.py`) — `.hc` → JSON, CLI + importable API.
* **Encoder** (`hcencrypt.py`) — JSON/values → `.hc`; supports **bit-exact
  round-trip** and slot mutation (e.g. swap the payload).
* **Legacy fallback** — old ≤4.x files (AES-ECB + `hc_reborn_*` keys +
  `[splitConfig]`) are still detected and decoded.
* Zero runtime dependencies beyond `pycryptodome`. No Android, no JVM.

## Install

```bash
pip install pycryptodome
git clone https://github.com/<user>/hctool.git
cd hctool
```

## Usage

### CLI

```bash
python3 hcdecrypt.py config.hc                  # app-style JSON to stdout
python3 hcdecrypt.py config.hc -o out.json      # write to file
python3 hcdecrypt.py config.hc --full           # all 32 slots, unfiltered
python3 hcdecrypt.py config.hc --raw            # + raw segments & transform trace
python3 hcdecrypt.py --self-test                # run built-in fixtures
python3 hcencrypt.py                            # bit-exact round-trip test
```

### Library

```python
from hcdecrypt import decrypt_hc_file

cfg = decrypt_hc_file("config.hc")
cfg.slots["sshField"]     # "host:port@user:pass"  (already decoded)
cfg.slots["payload"]      # HTTP request payload
cfg.metadata              # {"verApp": "645", "pingUrl": "dns.google"}
cfg.protections           # {"verCfg": "57"}
cfg.source_url            # origin URL of the config, if present
cfg.to_dict()             # app-shaped JSON
cfg.to_dict(full=True)    # all 32 slots
```

### Re-encoding (e.g. replace the payload)

```python
from hcdecrypt import decrypt_hc_file
from hcencrypt import encode_outer_raw, enc_raw, jkl_encode
import hcdecrypt as H

blob = open("config.hc", "rb").read()
outer, meta_raw, segments, url = H.extract_layers(blob)
vercfg = H.printable_prefix(H._field_plain(outer["b"], H.CHACHA_KEYS[7])).decode()

segments[0] = enc_raw(jkl_encode("CONNECT [host_port] HTTP/1.1[crlf][crlf]"),
                      H.CHACHA_KEYS[7])
open("patched.hc", "wb").write(encode_outer_raw(meta_raw, segments, vercfg, url))
```

---

## File format (verified)

### Layer map

```
L0  File is UTF-8 text. Each character contributes its BYTE VALUE
    (codepoint & 0xFF) — not its raw UTF-8 bytes.
L1  byte ^= XOR_KEY[i % 11]        XOR_KEY = e382e4b8adc386f09f9293
L2  L1 output is ASCII hex. hex-decode -> ciphertext of ChaCha20 "legacy"
    (8-byte nonce, block counter = 1), key table #5, nonce 0xdb*8.
    Plaintext is the outer JSON:
        {"a": {...}, "b": "...", "c": "..."}
L3  Outer fields (all chacha#7, drop the trailing 16 bytes):
        a.uv = slot delimiter          a.xy = 32-slot stream (key #1)
        a.vw = verApp                  a.rq = pingUrl
        "b"  = verCfg (protections)    "c"  = origin URL
L4  a.xy -> chacha#1 -> split on a.uv -> EXACTLY 32 segments.
L5  A segment is either:
        * plain text  -> "true", HTML notes, "[splitPsiphon]..." as-is
        * hex field   -> chacha#7, drop trailing 16 bytes:
              slot 0  payload         : JKL (1-2 rounds)
              slot 1  proxy           : base64 JKL (no chacha layer)
              slot 7  sshField        : JKL -> [BRAILLE] -> "host:port@user:pass"
              slot 11 ovpnUserAndPass : JKL
              slot 12 sni             : JKL
L6  JKL      = base64 -> per-byte T(key) -> base64,
               T(x) = ((x ^ 0xff) & 0xca) | (x & 0x35)
               key  = d5 d4 d3 d2 d1 d0 cf ce cd cc bd bc bb ba b9 b8 b7 b6 b5 b4
     BRAILLE  = 2 chars per byte, 4x16 Braille table
     creds    = numeric "A.B" pairs: byte = (A - IV) >> (B - IV);
                IV is per-section (e.g. 11 for an 11-byte user,
                45 for a 28-byte password) -> searched 0..255, scoring
                printable-ASCII output.
```

### ChaCha20 key table (32 bytes, hex)

| # | Role | Key |
|---|---|---|
| 5 | outer JSON container | `81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c` |
| 1 | 32-slot stream | `3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372` |
| 7 | metadata / slots / `b` / `c` | `3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea` |

All eight keys (indices 0–7) are listed in `hcdecrypt.py`.

### Slot names (in order)

`payload`, `proxy`, `lockAllConfig`, `blockedByRoot`, `expiryTime`,
`noteEnabled`, `notes`, `sshField`, `mobileDataAndLockProvider`,
`unlockUserAndPass`, `ovpnConfig`, `ovpnUserAndPass`, `sni`,
`unlockUserAndPass2`, `unknown14`, `blockedByHwid`, `cloudConfig`, `psiphon`,
`name`, `blockArea`, `connectionMode`, `blockedByPassword`, `unknown22`,
`extraSniffer`, `psiphon2`, `v2rayEnabled`, `v2rayConfig`, `version`,
`slowdnsEnabled`, `slowdnsServer`, `slowdnsPublickey`, `dnsResolver`

---

## Verification

Both test suites are green on every sample:

```
$ python3 hcdecrypt.py --self-test
[OK  ] clarovpn.hc          verApp=645 verCfg=57
[OK  ] XL_AXIS_V378.hc      verApp=645 verCfg=57
[OK  ] Servidor Claro.hc    verApp=645 verCfg=57
[OK  ] Servidor Movistar.hc verApp=645 verCfg=57
[OK  ] servidor tigo.hc     verApp=645 verCfg=57

$ python3 hcencrypt.py
[OK  ] round-trip Servidor Claro.hc    meta=True segmen=True slots=True
[OK  ] round-trip Servidor Movistar.hc meta=True segmen=True slots=True
[OK  ] round-trip Servidor mobile.hc   meta=True segmen=True slots=True
[OK  ] round-trip XL_AXIS_V378.hc      meta=True segmen=True slots=True
[OK  ] round-trip clarovpn.hc          meta=True segmen=True slots=True
[OK  ] round-trip servidor tigo.hc     meta=True segmen=True slots=True
```

Round-trip means: decode → re-encode from the encrypted layer → decode again,
and outer metadata, all 32 segments and every slot value are **identical**.

## Notes & limitations

* HTTP Custom **7.x** no longer uses the old scheme (AES-ECB + `hc_reborn_*`
  keys + `[splitConfig]`). That only applies to ≤4.x, which public tools such as
  `hcdecryptor`/`hcdrill` target — they fail on 7.x.
* Consumer keys/IVs are static, so "locked" only means *encrypted*, not bound to
  a device or account.
* Every encrypted field carries 16 trailing keystream bytes that the app
  discards; the encoder reproduces them so round-trips stay faithful.
* Slot 31 (`dnsResolver`) in some files holds only leftover keystream and is
  empty in the app; those values are normalised to `""` (raw hex is kept in the
  `--raw` transform trace).

## Samples

The `samples/` directory contains publicly distributed config files used as
decryption/round-trip fixtures. They are included **only as test vectors**; all
credentials belong to their respective providers. Replace them with your own
files if you fork this.

## Disclaimer

Provided for interoperability, malware/config analysis and authorised security
testing of your own configurations. You are responsible for complying with the
laws and terms that apply to you.

## License

MIT — see `LICENSE`.
