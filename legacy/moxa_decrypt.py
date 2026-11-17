#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
moxa_decrypt.py — recovery helper for a Moxa switch account password.

WHAT THIS PROGRAM DOES
    The 32-byte hex strings in the table are NOT hashes. They are the account
    password encrypted with a reversible 8-byte block cipher (DES / 3DES /
    Blowfish family) in CBC mode, with a key and IV baked into the device
    firmware.  The bundled synthetic examples all start with the 8 characters
    "EXAMPLE1", which is why every known row shares the same first ciphertext
    block:

        b76973fd38937651

    The password is written into a 32-byte buffer and padded with NUL bytes
    (a PKCS#7-to-32 variant is also tried).  CBC encryption then produces
    exactly four 8-byte blocks, stored as 64 hex characters.

HONEST LIMITATION
    The firmware key is not published.  This program can decrypt the unknown
    target password ONLY if it recovers that key first.  It does so by trying
    candidate keys against the known plaintext/ciphertext pairs (a dictionary
    attack, plus an optional numeric PIN brute-force).  A candidate is accepted
    only if it reproduces EVERY known pair.

    If the firmware key is a weak or well-known string, a match will be
    printed and the target password will be decrypted in full.  If the key is a
    strong random value, this program will not find it — supply a larger
    wordlist (--wordlist), or extract the key from the device firmware (.rom).

REQUIREMENTS
    Python 3.7+  and  pycryptodome
        Windows:  py -m pip install pycryptodome
        Linux:    pip3 install pycryptodome

USAGE
    python moxa_decrypt.py
    python moxa_decrypt.py --wordlist keys.txt
    python moxa_decrypt.py --pin 4
    python moxa_decrypt.py --key moxa --decrypt b76973fd38937651...
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from Crypto.Cipher import DES, DES3, Blowfish
except ImportError:
    sys.stderr.write(
        "pycryptodome is not installed.\n"
        "Install it with:\n"
        "    python -m pip install pycryptodome\n"
        "    (or:  py -m pip install pycryptodome)\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Synthetic known data (EXAMPLE1-prefix family + a couple of DEMO* samples).
# Ciphertexts were produced by the real ICS-G78xxA 5.x scheme in
# moxa_ics_password.py (not by ordinary CBC-DES).  They are bundled so the
# tool still has a consistent 8-byte-block table to inspect; the dictionary
# attack will not recover MOXA2DES, because that key is loaded without a
# standard DES key schedule.
# ---------------------------------------------------------------------------

# plaintext -> 32-byte value (64 hex chars).  Required constraints.
KNOWN_PAIRS: Dict[str, str] = {
    "EXAMPLE1":      "b76973fd38937651ddd17d6c045025abc6e06b247d2995f6fc4c4f26ba6b6e84",
    "EXAMPLE12":     "b76973fd389376510d253e774b47fdf847b331ea18e63cc1c339801c355be652",
    "EXAMPLE123":    "b76973fd3893765138579e75c65a6bd4f70f69c0f62f27b11721a6e8314e0436",
    "EXAMPLE1x":     "b76973fd38937651d94ae2311e3b6a0f49ce23b6a721105228d9515c5b8a450a",
    "EXAMPLE1ab":    "b76973fd389376513f1a54a8ecdf23ee98eacba8873234b6e16f140c6be3197f",
    "EXAMPLE1#":     "b76973fd389376517e7e8b8556458019e30e5c6aaf3d3fc3ac6d14b8f144e53b",
    "EXAMPLE1%":     "b76973fd3893765101e26ef0fb161c3e9cdbb7b4e1327d01b66b56603fc0888b",
    "EXAMPLE1pass":  "b76973fd389376511e7c922314fcf0c4c4c9b66f5a3271e56f18709e5f21d386",
    "EXAMPLE1user":  "b76973fd38937651e149872e7cc0da589fec7e3e23d3f2da04f7d3a5fb29d712",
    "EXAMPLE1!!":    "b76973fd3893765168e47897a079d5457b1fd1b224305e671d905a2ce9069c39",
    "EXAMPLE1xy":    "b76973fd389376517b3814b5aae34f54a994ba84786f6caf2752cc229a196191",
}

# Built-in synthetic target (password DEMOpass1).  First block differs
# because this plaintext does not start with "EXAMPLE1".
TARGET_HEX = (
    "45a42a46c47256a070d333343210fe58b045d9e622e643c54a25de5f7299ad6c"
)

# Reference-only rows (not used as required constraints).
# Another EXAMPLE1-prefix ciphertext, kept for a post-match check only.
SPACE_CT_HEX = (
    "b76973fd38937651e5161abbbf83238d0dd19974690715a0d0c88742ddbef770"
)
# Synthetic value with a different first block (plaintext DEMOuser1).
# Decrypted only if a key is found.
UNLABELLED_HEX = (
    "53a448fb1ddfc03370d333343210fe582eab637c88599c5e3b0dc8651f423b81"
)

BLOCK = 8
BUF_LEN = 32  # 4 blocks

PADDING_NULL = "null-to-32"
PADDING_PKCS7 = "pkcs7-to-32"


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------

def _configure_stdout() -> None:
    """Best-effort UTF-8 output (helps Windows consoles with special chars)."""
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf is not None:
            try:
                reconf(encoding="utf-8", errors="replace")
            except Exception:
                pass


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def as_blocks(data: bytes) -> List[bytes]:
    if len(data) % BLOCK != 0:
        raise ValueError("length is not a multiple of 8")
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]


def pad_password(password: str, scheme: str) -> bytes:
    raw = password.encode("latin-1")
    if len(raw) > BUF_LEN:
        raise ValueError("password is longer than the 32-byte buffer")
    if scheme == PADDING_NULL:
        return raw + b"\x00" * (BUF_LEN - len(raw))
    if scheme == PADDING_PKCS7:
        n = BUF_LEN - len(raw)
        return raw + bytes([n]) * n
    raise ValueError("unknown padding scheme: %s" % scheme)


def unpad_password(buf: bytes, scheme: str) -> bytes:
    if scheme == PADDING_NULL:
        return buf.rstrip(b"\x00")
    if scheme == PADDING_PKCS7:
        if not buf:
            return buf
        n = buf[-1]
        if 1 <= n <= BUF_LEN and buf.endswith(bytes([n]) * n):
            return buf[:-n]
        return buf.rstrip(b"\x00")
    return buf.rstrip(b"\x00")


def cbc_encrypt(encrypt_block: Callable[[bytes], bytes], iv: bytes, pt: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for block in as_blocks(pt):
        c = encrypt_block(xor(block, prev))
        out.extend(c)
        prev = c
    return bytes(out)


def cbc_decrypt(decrypt_block: Callable[[bytes], bytes], iv: bytes, ct: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for block in as_blocks(ct):
        out.extend(xor(decrypt_block(block), prev))
        prev = block
    return bytes(out)


# ---------------------------------------------------------------------------
# Model: raw single-block known-plaintext pairs (IV-free)
# ---------------------------------------------------------------------------

RawPair = Tuple[bytes, bytes]  # (cipher_input, cipher_output)


def raw_pairs_for(pairs: Dict[str, str], scheme: str) -> List[RawPair]:
    """CBC identity C_i = E(P_i XOR C_{i-1}) gives raw E() pairs, no IV needed.

    Block 1 is skipped: C1 = E(P1 XOR IV) still contains the unknown IV.
    Blocks 2..4 of every known row are used.
    """
    result: List[RawPair] = []
    seen = set()
    for password, hex_ct in pairs.items():
        pt = pad_password(password, scheme)
        ct = bytes.fromhex(hex_ct)
        if len(ct) != BUF_LEN:
            raise ValueError("ciphertext for %r is not 32 bytes" % password)
        for off in range(BLOCK, BUF_LEN, BLOCK):
            inp = xor(pt[off:off + BLOCK], ct[off - BLOCK:off])
            out = ct[off:off + BLOCK]
            key = (inp, out)
            if key not in seen:
                seen.add(key)
                result.append(key)
    return result


def model_is_consistent(pairs: Dict[str, str], scheme: str) -> Tuple[bool, str]:
    """Same raw input must always map to the same output."""
    mapping: Dict[bytes, bytes] = {}
    conflicts = 0
    for inp, out in raw_pairs_for(pairs, scheme):
        prev = mapping.get(inp)
        if prev is None:
            mapping[inp] = out
        elif prev != out:
            conflicts += 1
    ok = conflicts == 0 and len(mapping) > 0
    msg = (
        "padding=%s  unique raw E() pairs=%d  conflicts=%d  %s"
        % (scheme, len(mapping), conflicts, "OK" if ok else "INCONSISTENT")
    )
    return ok, msg


# ---------------------------------------------------------------------------
# Ciphers and key-length handling
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CipherSpec:
    name: str
    lengths: Tuple[int, ...]   # accepted key lengths (Blowfish uses a range)
    min_len: int = 0
    max_len: int = 0

    def accepts(self, n: int) -> bool:
        if self.lengths:
            return n in self.lengths
        return self.min_len <= n <= self.max_len


CIPHERS = [
    CipherSpec("DES", (8,)),
    CipherSpec("3DES", (16, 24)),
    CipherSpec("Blowfish", (), min_len=4, max_len=56),
]

EXTRA_CIPHERS_NOTE = (
    "CAST-128 and RC2 are available via --extra-ciphers "
    "(same 8-byte block size, also in pycryptodome)."
)


def _load_extra_ciphers() -> List[CipherSpec]:
    extra: List[CipherSpec] = []
    try:
        from Crypto.Cipher import CAST  # noqa: F401
        extra.append(CipherSpec("CAST", (), min_len=5, max_len=16))
    except ImportError:
        pass
    try:
        from Crypto.Cipher import ARC2  # noqa: F401
        extra.append(CipherSpec("RC2", (), min_len=5, max_len=128))
    except ImportError:
        pass
    return extra


def make_ecb(name: str, key: bytes):
    """Return a pycryptodome ECB cipher, or None if the key is rejected."""
    try:
        if name == "DES":
            if len(key) != 8:
                return None
            return DES.new(key, DES.MODE_ECB)
        if name == "3DES":
            if len(key) not in (16, 24):
                return None
            return DES3.new(key, DES3.MODE_ECB)
        if name == "Blowfish":
            if not 4 <= len(key) <= 56:
                return None
            return Blowfish.new(key, Blowfish.MODE_ECB)
        if name == "CAST":
            from Crypto.Cipher import CAST
            if not 5 <= len(key) <= 16:
                return None
            return CAST.new(key, CAST.MODE_ECB)
        if name == "RC2":
            from Crypto.Cipher import ARC2
            if not 5 <= len(key) <= 128:
                return None
            return ARC2.new(key, ARC2.MODE_ECB)
    except ValueError:
        return None
    return None


def expand_key_material(raw: bytes) -> List[bytes]:
    """Pad / truncate / repeat a candidate into legal key lengths.

    Variants tried for every candidate:
      * NUL-padded / truncated to 8, 16, 24 (and 4..16 for Blowfish/CAST)
      * space-padded to the same lengths
      * repeated to fill the same lengths
      * the raw bytes themselves, if already a legal length
      * first 8 / 16 / 24 bytes of MD5, SHA-1 and SHA-256 of the raw bytes
    Duplicates are removed.  3DES keys that would degrade to single DES are
    still emitted; pycryptodome will reject them and they are skipped.
    """
    out = set()

    def pad_to(n: int, fill: bytes) -> bytes:
        if len(raw) >= n:
            return raw[:n]
        return raw + fill * (n - len(raw))

    def repeat_to(n: int) -> bytes:
        if not raw:
            return bytes(n)
        return (raw * (n // len(raw) + 1))[:n]

    for n in (8, 16, 24):
        out.add(pad_to(n, b"\x00"))
        out.add(pad_to(n, b" "))
        out.add(repeat_to(n))

    if 4 <= len(raw) <= 56:
        out.add(raw)

    # Hash-derived material (common embedded-device pattern).
    for digest in (
        hashlib.md5(raw).digest(),
        hashlib.sha1(raw).digest(),
        hashlib.sha256(raw).digest(),
    ):
        out.add(digest[:8])
        out.add(digest[:16])
        out.add(digest[:24])

    return [k for k in out if k]


# ---------------------------------------------------------------------------
# Built-in wordlist of plausible firmware keys
# ---------------------------------------------------------------------------

def builtin_wordlist() -> List[bytes]:
    words = [
        # vendor / product
        "moxa", "MOXA", "Moxa", "MoXa", "MoxA",
        "moxa123", "moxa1234", "moxa12345", "moxa123456",
        "moxa1234567", "moxa12345678", "moxa123456789",
        "moxaadmin", "moxapass", "moxapassword", "moxakey", "moxa_key",
        "moxakey1", "MOXA123", "MOXA1234", "MOXApass", "moxamoxa",
        "MOXAMOXA", "moxa moxa", "moxatech", "MOXATECH",
        "Moxa Technologies", "Moxa Technologies Co.",
        "Moxa Technologies Co., Ltd.", "MOXA INC", "MOXA Inc.",
        "MOXA Inc", "moxaiwroot", "moxaroot", "moxauser",
        # default login / generic
        "admin", "Admin", "ADMIN", "administrator", "Administrator",
        "root", "Root", "ROOT", "user", "User", "guest", "Guest",
        "password", "Password", "PASSWORD", "pass", "passwd", "passw0rd",
        "default", "Default", "DEFAULT", "defaultpw", "default1",
        "changeme", "letmein", "trustno1", "qwerty", "qwertyui",
        "admin123", "admin1234", "root1234", "password1", "adminadmin",
        "1234", "12345", "123456", "1234567", "12345678", "123456789",
        "1234567890", "0000", "00000000", "11111111", "88888888",
        "666666", "888888", "01234567", "0123456789abcdef",
        "abcdefgh", "ABCDEFGH", "aaaabbbb", "abcd1234",
        "private", "secret", "Secret", "SECRET", "public", "Public",
        "cisco", "Cisco", "CISCO",
        # the synthetic example passwords and pieces of them
        "EXAMPLE1", "EXAMPLE12", "EXAMPLE123", "EXAMPLE1pass",
        "EXAMPLE1user", "DEMOpass1", "DEMOuser1",
        # product-line / model strings (4000 DIN-rail, 7000 4U, related)
        "EDS", "eds", "EDS-G512E", "EDSG512E", "eds-g512e", "EDS_G512E",
        "MDS", "mds", "MDS-G4000", "MDSG4000", "mds-g4000",
        "ICS", "ics", "ICS-G7700A", "ICS-G7800A", "ICSG7700A", "ICSG7800A",
        "ICS-G7700", "ICS-G7800", "icsg7700", "icsg7800",
        "PT-G7728", "PT-G7828", "PTG7728", "PTG7828",
        "PT-7528", "PT-7828", "PT7528", "PT7828",
        "switch", "Switch", "SWITCH", "ethernet", "Ethernet",
        "industrial", "Industrial", "modular", "Modular",
        "dinrail", "DINRAIL", "DIN-RAIL", "din-rail",
        "MOXA-EDS", "moxaeds", "edspass",
        # tools / config-file key string (MX-ROS default is "moxa")
        "MXconfig", "mxconfig", "MXConfig", "MXview", "mxview", "MXView",
        "MX-ROS", "MXROS", "mxros", "keystring", "KeyString", "Key String",
        "pre-shared", "preshared", "psk", "PSK", "presharedkey",
        "encryption", "Encryption", "encrypt", "Encrypt", "key", "Key", "KEY",
        "des", "DES", "3des", "3DES", "blowfish", "Blowfish", "BLOWFISH",
        "cbc", "CBC", "ecb", "ECB", "chall", "challenge", "CHALL", "Challenge",
        # default management IPs often used on Moxa
        "192.168.127.253", "192.168.127.254", "192168127253", "192168127254",
        "192.168.1.1", "192.168.0.1", "10.0.0.1",
        "255.255.255.0", "2552552550",
        # empty / trivial
        "", " ", "  ", "moxa/admin", "admin/moxa", "admin:moxa", "moxa:admin",
    ]
    # case variants
    expanded: List[str] = []
    seen = set()
    for w in words:
        for v in (w, w.lower(), w.upper(), w.capitalize()):
            if v not in seen:
                seen.add(v)
                expanded.append(v)

    result: List[bytes] = [v.encode("utf-8") for v in expanded]

    # Raw binary patterns worth a cheap try.
    result.append(b"")
    result.append(bytes.fromhex("b76973fd38937651"))          # the constant C1
    result.append(b"EXAMPLE1")
    for n in (8, 16, 24):
        result.append(b"\x00" * n)
        result.append(b"\xff" * n)
        result.append(b"\x01" * n)
        result.append(b"\x12" * n)
    result.append(bytes(range(8)))
    result.append(bytes(range(1, 9)))
    result.append(bytes(range(16)))
    result.append(bytes(range(24)))
    # Classic DES weak / semi-weak keys
    for hx in (
        "0101010101010101", "FEFEFEFEFEFEFEFE",
        "E0E0E0E0F1F1F1F1", "1F1F1F1F0E0E0E0E",
        "01FE01FE01FE01FE", "FE01FE01FE01FE01",
        "1FE01FE00EF10EF1", "E01FE01FF10EF10E",
    ):
        result.append(bytes.fromhex(hx))
    # Single-byte-repeated 8/16/24-byte keys (256 * 3, cheap)
    for b in range(256):
        result.append(bytes([b]) * 8)
        result.append(bytes([b]) * 16)
        result.append(bytes([b]) * 24)
    return result


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@dataclass
class Match:
    cipher: str
    key: bytes
    iv: bytes
    padding: str
    source: str


def _key_preview(key: bytes) -> str:
    hx = key.hex()
    try:
        txt = key.decode("ascii")
        if txt.isprintable() or all(ch in "\x00\t\n\r " or ch.isprintable() for ch in txt):
            shown = repr(txt)
            return "%s  (ascii %s, %d bytes)" % (hx, shown, len(key))
    except UnicodeDecodeError:
        pass
    return "%s  (%d bytes)" % (hx, len(key))


def test_raw(encrypt_block: Callable[[bytes], bytes], pairs: Sequence[RawPair]) -> bool:
    # Cheap reject on the first pair, then confirm all.
    for inp, out in pairs:
        if encrypt_block(inp) != out:
            return False
    return True


def recover_iv_and_verify(
    encrypt_block: Callable[[bytes], bytes],
    decrypt_block: Callable[[bytes], bytes],
    scheme: str,
    pairs: Dict[str, str],
) -> Optional[bytes]:
    """Derive IV from the first known pair, then re-encrypt every pair."""
    first_pw, first_ct = next(iter(pairs.items()))
    pt = pad_password(first_pw, scheme)
    ct = bytes.fromhex(first_ct)
    iv = xor(pt[:BLOCK], decrypt_block(ct[:BLOCK]))
    for password, hex_ct in pairs.items():
        produced = cbc_encrypt(encrypt_block, iv, pad_password(password, scheme))
        if produced != bytes.fromhex(hex_ct):
            return None
    return iv


def iter_candidates(
    extras: Sequence[bytes],
    pin_digits: int,
    include_builtin: bool,
) -> Iterable[Tuple[bytes, str]]:
    """Yield (raw_material, source-label) without expanding key lengths yet."""
    if include_builtin:
        for raw in builtin_wordlist():
            yield raw, "built-in wordlist"
    for raw in extras:
        yield raw, "wordlist/key argument"
    if pin_digits > 0:
        limit = 10 ** pin_digits
        width = pin_digits
        for n in range(limit):
            yield ("%0*d" % (width, n)).encode("ascii"), "numeric PIN"


def search_keys(
    ciphers: Sequence[CipherSpec],
    padding_schemes: Sequence[str],
    extras: Sequence[bytes],
    pin_digits: int,
    include_builtin: bool,
    progress_every: int,
) -> Optional[Match]:
    raw_by_scheme = {s: raw_pairs_for(KNOWN_PAIRS, s) for s in padding_schemes}

    tested_keys = 0
    tested_combos = 0
    seen_key: set = set()
    t0 = time.time()
    last_report = t0

    def report(force: bool = False) -> None:
        nonlocal last_report
        now = time.time()
        if not force and (now - last_report) < 1.0:
            return
        # Skip a forced end-of-search line if the run was short and we
        # never printed progress — keeps the output tidy on a quick miss.
        if force and last_report == t0 and (now - t0) < 1.5:
            return
        last_report = now
        elapsed = max(now - t0, 1e-6)
        sys.stderr.write(
            "  ... tried %d key-materials, %d cipher/key combos  (%.0f combos/s)\n"
            % (tested_keys, tested_combos, tested_combos / elapsed)
        )
        sys.stderr.flush()

    for raw, source in iter_candidates(extras, pin_digits, include_builtin):
        variants = expand_key_material(raw)
        for key in variants:
            marker = key
            if marker in seen_key:
                continue
            seen_key.add(marker)
            tested_keys += 1
            if progress_every and tested_keys % progress_every == 0:
                report()
            for spec in ciphers:
                if not spec.accepts(len(key)):
                    # Blowfish/CAST/RC2 use a range; DES/3DES use exact lengths
                    # already filtered by expand_key_material + accepts().
                    continue
                cipher = make_ecb(spec.name, key)
                if cipher is None:
                    continue
                tested_combos += 1
                encrypt_block = cipher.encrypt
                for scheme in padding_schemes:
                    pairs = raw_by_scheme[scheme]
                    if not test_raw(encrypt_block, pairs):
                        continue
                    # Raw pairs matched: recover IV and confirm full CBC.
                    # Need a fresh cipher for decrypt (ECB objects are fine
                    # to reuse for both directions).
                    dec = make_ecb(spec.name, key)
                    if dec is None:
                        continue
                    iv = recover_iv_and_verify(
                        encrypt_block, dec.decrypt, scheme, KNOWN_PAIRS
                    )
                    if iv is None:
                        continue
                    report(force=True)
                    return Match(
                        cipher=spec.name,
                        key=key,
                        iv=iv,
                        padding=scheme,
                        source=source,
                    )
    report(force=True)
    return None


# ---------------------------------------------------------------------------
# Decrypt / display
# ---------------------------------------------------------------------------

def decrypt_hex(match: Match, hex_ct: str) -> bytes:
    ct = bytes.fromhex(hex_ct.strip())
    if len(ct) != BUF_LEN:
        raise ValueError("expected 32 bytes (64 hex characters), got %d bytes" % (len(ct),))
    cipher = make_ecb(match.cipher, match.key)
    if cipher is None:
        raise RuntimeError("cipher refused the matched key on decrypt")
    return cbc_decrypt(cipher.decrypt, match.iv, ct)


def format_plaintext(buf: bytes, scheme: str) -> str:
    body = unpad_password(buf, scheme)
    parts = ["    raw 32-byte buffer, hex : %s" % buf.hex()]
    parts.append("    after stripping pad, hex: %s" % body.hex())
    try:
        txt = body.decode("ascii")
        parts.append("    as ASCII text           : %s" % txt)
    except UnicodeDecodeError:
        txt = body.decode("latin-1", errors="replace")
        parts.append("    as Latin-1 text         : %s" % txt)
    # Visible whitespace / non-printables
    shown = "".join(
        ch if (32 <= ord(ch) < 127) else "\\x%02x" % ord(ch)
        for ch in body.decode("latin-1")
    )
    parts.append("    printable view          : %s" % shown)
    return "\n".join(parts)


def print_match(match: Match) -> None:
    print()
    print("=" * 72)
    print("KEY FOUND")
    print("=" * 72)
    print("  cipher  : %s" % match.cipher)
    print("  mode    : CBC")
    print("  padding : %s" % match.padding)
    print("  key     : %s" % _key_preview(match.key))
    print("  IV      : %s  (%d bytes)" % (match.iv.hex(), len(match.iv)))
    print("  source  : %s" % match.source)
    print()
    print("Sanity: re-encrypting every known pair with this key...")
    cipher = make_ecb(match.cipher, match.key)
    assert cipher is not None
    ok = True
    for password, hex_ct in KNOWN_PAIRS.items():
        produced = cbc_encrypt(
            cipher.encrypt, match.iv, pad_password(password, match.padding)
        )
        if produced.hex() != hex_ct.lower():
            print("  FAIL  %r" % password)
            ok = False
        else:
            print("  OK    %r" % password)
    print("  %s" % ("All known pairs reproduced." if ok else "WARNING: some pairs did not match."))
    print()
    print("Decrypted built-in target:")
    pt = decrypt_hex(match, TARGET_HEX)
    print(format_plaintext(pt, match.padding))
    print()
    # Reference rows
    print("Reference row with trailing space(s), ciphertext %s:" % SPACE_CT_HEX)
    print(format_plaintext(decrypt_hex(match, SPACE_CT_HEX), match.padding))
    print()
    print("Unlabelled top-of-table value %s:" % UNLABELLED_HEX)
    print(format_plaintext(decrypt_hex(match, UNLABELLED_HEX), match.padding))
    print()
    print("To decrypt another 32-byte hex value with this key:")
    print("  python moxa_decrypt.py --key-hex %s --cipher %s --iv %s --padding %s --decrypt <64-hex>"
          % (match.key.hex(), match.cipher, match.iv.hex(), match.padding))
    print("=" * 72)


# ---------------------------------------------------------------------------
# Self-test (synthetic key, proves the engine works even if firmware key is not found)
# ---------------------------------------------------------------------------

def run_selftest() -> int:
    print("Self-test 1/2: CBC / 8-byte-block model on the synthetic known pairs")
    any_ok = False
    for scheme in (PADDING_NULL, PADDING_PKCS7):
        ok, msg = model_is_consistent(KNOWN_PAIRS, scheme)
        print("  %s" % msg)
        any_ok = any_ok or ok
    # Structural checks that do not depend on the key
    c1 = {bytes.fromhex(h)[:8] for h in KNOWN_PAIRS.values()}
    print("  unique first blocks: %d  (expect 1, value %s)"
          % (len(c1), next(iter(c1)).hex()))
    # AES (16-byte block) is incompatible with a constant first 8 bytes
    # while bytes 8..15 of the plaintext change.
    print("  first 8 bytes constant while P2 changes => block size is 8, not 16 (AES ruled out).")
    if not any_ok:
        print("SELF-TEST FAILED: known pairs are not consistent with an 8-byte CBC model.")
        return 1

    print()
    print("Self-test 2/2: planted DES key must be recovered from synthetic pairs")
    planted_key = b"s3lfT3st"
    planted_iv = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    cipher = DES.new(planted_key, DES.MODE_ECB)
    synthetic = {}
    for password in KNOWN_PAIRS:
        ct = cbc_encrypt(cipher.encrypt, planted_iv, pad_password(password, PADDING_NULL))
        synthetic[password] = ct.hex()
    # Temporarily swap KNOWN_PAIRS? Better: test the helpers directly.
    raw = raw_pairs_for(synthetic, PADDING_NULL)
    if not test_raw(cipher.encrypt, raw):
        print("SELF-TEST FAILED: planted key does not satisfy its own raw pairs.")
        return 1
    iv = recover_iv_and_verify(cipher.encrypt, cipher.decrypt, PADDING_NULL, synthetic)
    if iv != planted_iv:
        print("SELF-TEST FAILED: recovered IV %r != planted IV %r" % (iv, planted_iv))
        return 1
    # And a negative: a wrong key must be rejected
    wrong = DES.new(b"wrongKey", DES.MODE_ECB)
    if test_raw(wrong.encrypt, raw):
        print("SELF-TEST FAILED: a wrong key was accepted.")
        return 1
    print("  planted key recovered, IV matches, wrong key rejected.  OK")
    print("Self-test passed.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_wordlist_file(path: str) -> List[bytes]:
    out: List[bytes] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.lower().startswith("hex:"):
                body = s[4:].strip().replace(" ", "")
                try:
                    out.append(bytes.fromhex(body))
                except ValueError as exc:
                    raise SystemExit("wordlist %s line %d: bad hex: %s" % (path, lineno, exc))
            elif s.lower().startswith("0x"):
                body = s[2:].strip().replace(" ", "")
                try:
                    out.append(bytes.fromhex(body))
                except ValueError as exc:
                    raise SystemExit("wordlist %s line %d: bad hex: %s" % (path, lineno, exc))
            else:
                out.append(s.encode("utf-8"))
    return out


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="moxa_decrypt.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Try to recover a Moxa switch account password from its encrypted\n"
            "32-byte hex value by dictionary-attacking the firmware key."
        ),
        epilog=(
            "examples:\n"
            "  python moxa_decrypt.py\n"
            "  python moxa_decrypt.py --wordlist keys.txt\n"
            "  python moxa_decrypt.py --pin 4\n"
            "  python moxa_decrypt.py --selftest\n"
            "  python moxa_decrypt.py --key-hex 6d6f786100000000 --cipher DES "
            "--iv 0011223344556677 --decrypt b76973fd...\n"
            "\n"
            "wordlist format: one candidate per line, UTF-8.  Lines starting with\n"
            "# are comments.  A raw binary key can be given as  hex:0011223344556677\n"
            "or  0x0011223344556677.\n"
            "\n"
            + EXTRA_CIPHERS_NOTE
        ),
    )
    p.add_argument(
        "--wordlist", "-w", metavar="FILE",
        help="extra key candidates, one per line (UTF-8)",
    )
    p.add_argument(
        "--pin", metavar="DIGITS", type=int, default=0,
        help="also brute-force numeric PINs of this length (e.g. --pin 4 "
             "tries 0000..9999).  Default: off.  --pin 7+ will take a long time.",
    )
    p.add_argument(
        "--key", metavar="TEXT",
        help="test one specific key string (still expanded to legal lengths)",
    )
    p.add_argument(
        "--key-hex", metavar="HEX",
        help="test one specific key given as hex (also still expanded)",
    )
    p.add_argument(
        "--cipher", metavar="NAME",
        help="with --key-hex and --iv, skip the search and just decrypt "
             "(DES, 3DES, Blowfish, or CAST / RC2 if --extra-ciphers)",
    )
    p.add_argument(
        "--iv", metavar="HEX",
        help="IV to use with --key-hex --cipher --decrypt (16 hex chars)",
    )
    p.add_argument(
        "--padding", metavar="SCHEME",
        choices=(PADDING_NULL, PADDING_PKCS7),
        help="padding scheme to use with a manually supplied key "
             "(null-to-32 or pkcs7-to-32)",
    )
    p.add_argument(
        "--decrypt", metavar="HEX",
        help="decrypt a 32-byte (64 hex character) value once a key is known. "
             "If a search is also requested, it runs first.  The built-in target "
             "target is always decrypted automatically when a key is found.",
    )
    p.add_argument(
        "--extra-ciphers", action="store_true",
        help="also try CAST-128 and RC2 (same 8-byte block size)",
    )
    p.add_argument(
        "--no-builtin", action="store_true",
        help="do not use the built-in wordlist (only --wordlist / --key / --pin)",
    )
    p.add_argument(
        "--progress", metavar="N", type=int, default=2000,
        help="print progress every N unique key-materials (default: 2000)",
    )
    p.add_argument(
        "--selftest", action="store_true",
        help="verify the CBC model and the search engine, then exit",
    )
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_stdout()
    args = parse_args(argv)

    if args.selftest:
        return run_selftest()

    print("moxa_decrypt.py — Moxa account-password recovery helper", flush=True)
    print("The table values are reversible CBC encryptions, not hashes.")
    print("This program works only if the firmware key is among the tried candidates.")
    print()

    print("Checking the 8-byte CBC model against the known pairs...")
    model_ok = False
    for scheme in (PADDING_NULL, PADDING_PKCS7):
        ok, msg = model_is_consistent(KNOWN_PAIRS, scheme)
        print("  %s" % msg)
        model_ok = model_ok or ok
    if not model_ok:
        print()
        print("The known pairs are not consistent with an 8-byte CBC model.")
        print("Refusing to search: a key found under a broken model would be meaningless.")
        return 2
    print("  Model holds: one deterministic 8-byte block cipher in CBC mode.")
    print("  (CFB and ECB were ruled out earlier; a 16-byte block / AES is")
    print("   incompatible with a constant first ciphertext block.)")
    print()

    ciphers = list(CIPHERS)
    if args.extra_ciphers:
        extra = _load_extra_ciphers()
        ciphers.extend(extra)
        print("Ciphers: %s" % ", ".join(c.name for c in ciphers))
    else:
        print("Ciphers: DES, 3DES, Blowfish  (add --extra-ciphers for CAST-128 and RC2)")
    print("Padding schemes tried: %s, %s" % (PADDING_NULL, PADDING_PKCS7))
    print()

    # Direct decrypt with a fully specified key/IV (no search).
    if args.cipher and args.key_hex and args.iv:
        key = bytes.fromhex(args.key_hex.strip())
        iv = bytes.fromhex(args.iv.strip())
        scheme = args.padding or PADDING_NULL
        cipher = make_ecb(args.cipher, key)
        if cipher is None:
            print("Cannot build %s with a %d-byte key." % (args.cipher, len(key)))
            return 2
        match = Match(args.cipher, key, iv, scheme, "command line")
        hex_ct = args.decrypt or TARGET_HEX
        print("Decrypting with the supplied key, no search.")
        print(format_plaintext(decrypt_hex(match, hex_ct), scheme))
        return 0

    extras: List[bytes] = []
    if args.wordlist:
        extras.extend(load_wordlist_file(args.wordlist))
        print("Loaded %d candidates from %s" % (len(extras), args.wordlist))
    if args.key is not None:
        extras.append(args.key.encode("utf-8"))
    if args.key_hex:
        extras.append(bytes.fromhex(args.key_hex.strip()))

    pin_digits = args.pin or 0
    if pin_digits < 0 or pin_digits > 10:
        print("--pin must be between 0 and 10")
        return 2
    if pin_digits >= 7:
        n = 10 ** pin_digits
        print()
        print("WARNING: --pin %d will try %d numeric keys, each expanded into" % (pin_digits, n))
        print("several length variants and run through every cipher.  This can take hours.")
        print("A 4-digit PIN is typically a few seconds; 6-digit, a few minutes.")
        print()
    if pin_digits:
        print("Numeric PIN brute-force enabled: %0*d .. %0*d"
              % (pin_digits, 0, pin_digits, 10 ** pin_digits - 1))

    include_builtin = not args.no_builtin
    if include_builtin:
        print("Built-in wordlist: vendor defaults, model names, DES weak keys,")
        print("repeated-byte keys, and hash-derived variants of each candidate.")
    else:
        print("Built-in wordlist disabled (--no-builtin).")
    print()
    print("Searching...", flush=True)

    t0 = time.time()
    match = search_keys(
        ciphers=ciphers,
        padding_schemes=(PADDING_NULL, PADDING_PKCS7),
        extras=extras,
        pin_digits=pin_digits,
        include_builtin=include_builtin,
        progress_every=max(1, args.progress),
    )
    elapsed = time.time() - t0
    print("Search finished in %.1f seconds." % elapsed)

    if match is None:
        print()
        print("=" * 72)
        print("NO KEY FOUND")
        print("=" * 72)
        print("The firmware key is not among the candidates that were tried.")
        print("The target password cannot be decrypted without that key.")
        print()
        print("What you can do next:")
        print("  1. Run again with a larger wordlist:")
        print("         python moxa_decrypt.py --wordlist keys.txt")
        print("     (one candidate per line; use  hex:0011223344556677  for raw keys).")
        print("  2. If you suspect a short numeric key:  python moxa_decrypt.py --pin 4")
        print("  3. Best path if a dictionary attack fails: take the device firmware")
        print("     image (.rom) from the vendor or a backup, and extract the baked-in")
        print("     key from it.  Once you have the key:")
        print("         python moxa_decrypt.py --key-hex ... --cipher DES --iv ... --decrypt ...")
        print("  4. Or use the original Moxa tool / the same switch that produced the")
        print("     table: feed it more candidate passwords and compare the output with")
        print("     the target value (that tool already holds the key).")
        print("=" * 72)
        return 1

    print_match(match)
    if args.decrypt:
        print()
        print("Extra value requested via --decrypt:")
        print(format_plaintext(decrypt_hex(match, args.decrypt), match.padding))
    return 0


if __name__ == "__main__":
    sys.exit(main())
