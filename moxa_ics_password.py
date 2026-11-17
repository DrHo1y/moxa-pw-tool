#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Moxa ICS-G7852A / ICS-G7800A (FW 5.x) — расшифровка PasswordEncryp из конфигурации.

Проверено на прошивках v5.6 (Build_18110819), v5.9 и v5.12.
Зависимостей нет, нужен только Python 3 (стандартная библиотека).

Примеры:
  py moxa_ics_password.py
  py moxa_ics_password.py 45a42a46c47256a070d333343210fe58b045d9e622e643c54a25de5f7299ad6c
  py moxa_ics_password.py --encrypt "DEMOpass1"
  py moxa_ics_password.py --selftest
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from typing import Optional, Tuple

# Ключ из прошивки ICS-G7852A (ASCII, 8 байт). В коде он копируется
# в 128-байтный DES key schedule БЕЗ развёртки (остальные 120 байт — нули).
KEY = b"MOXA2DES"

# Встроенный синтетический пример (пароль DEMOpass1).
# 64 hex-символа = 16 байт шифртекста + 16 байт MD5.
DEFAULT_TARGET = (
    "45a42a46c47256a070d333343210fe58b045d9e622e643c54a25de5f7299ad6c"
)

# S/P-таблицы DES из прошивки (8 таблиц по 64 слова, little-endian).
_SP_B64 = """
AAgIAgAACAACAAACAggIAgAAAAICCAgAAgAIAAIAAAICCAgAAAgIAgAACAICCAAAAggAAgAAAAIA
AAAAAgAIAAAACAACAAAAAAgAAgAICAACCAgCAAAIAgIIAAAACAACAgAAAAAIAAAACAgAAgAIAgAI
AAACCAACAgAIAgAAAAAAAAAAAggIAgAIAAICAAgAAAgIAgAACAACCAAAAAgAAgIACAIACAAAAAgI
AAIAAAICCAgAAgAAAAIAAAIAAAgCAggIAgAICAAAAAgCAggAAgAAAAICCAAAAgAIAAAAAAAAAAgA
AAAAAgIIAAIACAgCAgAAAAIACAIACAAAAggIABCAEEAAAAAAAIAQAAAAEEAQAABAEIAAAACAAEAA
gBAAAIAAABAAEEAQAAAAAIAAQBAAEAAAgBBAAAAQQBAAAAAAABAAEIAAQBAAEEAAgAAAEIAQAAAA
AEAAAAAAEAAQABCAAEAQgBAAAIAQQBAAAEAAAABAAAAQABCAAAAQgBBAEAAQAACAEEAAgABAEIAQ
ABCAEEAQABAAEAAAQAAAAAAAAABAEIAAAAAAEAAQABBAAIAAAAAAAEAQgBAAEIAAQACAEEAAgAAA
AAAAABAAAEAQAAAAEIAQQACAEAAAABBAEAAQQAAAEAAQgAAAAIAAQBCAAEAQAAAAAAAQQACAEAAB
AAAEAAEEBAABAAABAQAEAQAEAAAAAAQBAQAEAAEEAAABAAQAAAQAAAAEBAEAAAABAQQEAQEAAAEA
AAABAAQEAAAAAAEABAAAAQQEAAEAAAEBAAABAQQEAAAEAAEAAAQBAAQEAAEABAEBBAAAAAQEAAEE
AAAAAAAAAAAEAQEEAAABBAQAAQAAAQAAAAAABAABAQAAAQAEAAAABAQBAQAEAAAAAAABBAQAAQQA
AQAEBAEABAAAAAAEAQEEBAEAAAABAQQAAQAABAAAAAQBAQQEAAAEAAABAAQBAQAEAAEEAAABAAQA
AAAAAQAEBAEBAAABAAAEAQEEAAABAAAAAAQECBBAAAAQABAIAAAACBBAEAAAAAAAAEAQCBAAEAgA
QAAAEEAQCAAAEAAAABAIEAAACAAAEAgQQAAAAEAAAAAAEAgAQBAAEEAAABAAAAgAAAAAEEAACBAA
EAAAQBAAEAAACBAAAAAAAAAIAEAAABBAEAAQABAIAEAQCBBAEAAAQAAIAEAQCBAAAAAAQAAIAAAQ
ABBAAAAQABAIAAAAAABAEAgQABAAAAAAABAAAAgAQAAAAAAACABAEAAQQBAAEAAAAAAAEAgQQBAI
EEAAAABAAAgQQBAIAAAAABAAEAgQQAAIAEAAABBAAAAAQBAIEAAQCBAAAAAAABAIAAAQABBAEAAA
AAgAAAEAAAQAACAEAQggAAEIAAQACCAEAQAAAAEIAAABACAAAAAgAAAIAAQBACAEAAggAAEIAAQB
CAAAAAAABAEAAAAACCAAAQAgBAAAAAQACCAEAQAAAAAAIAAACCAAAAAgBAAIIAQBCCAAAQAAAAEI
AAQAACAEAAAABAEIAAQBCCAEAAggAAEAAAABCAAAAQAgAAAAIAAACAAEAAgAAAAIAAQBACAEAQgA
AAAAIAQBAAAAAAgABAAAIAABACAEAAgABAAAAAAAACAEAQggAAEIAAQBCCAEAAAAAAEAAAQBACAA
AQgABAAIIAQAACAAAAAgBAEAAAABCCAAAAhAAACAQAAgAAAAAAAAICCAQAAgAAAgAABAIACAAAAg
AEAgAABAICCAACAgAAAAAIAAIACAQAAAgAAAIIBAICAAAAAgAEAgAIBAACCAAAAAAAAgAABAAAAA
ACAggEAAIIBAICCAAAAggAAAAIBAIAAAQAAAAAAgIABAICAAACAAgEAgAAAAAACAACAAgEAgIAAA
ICCAQAAgAAAAAAAAIACAAAAAgAAgAABAACCAAAAgAEAAIABAICCAACAgAEAAAABAICCAACAgAAAA
IABAIACAQAAAgAAAIIBAICAAAAAAAAAgAABAAACAQCAAgAAgIIAAACCAQCAAAEAAAABAACCAAEAA
AAACAAAAAgABBAAAAQRCAAEEQAAAAEIAAAAAAAAAAAABBAIAAQQCAAAAQAABBAAAAABCAAEAQAAB
BAIAAAQCAAEAQAAABEAAAARCAAEAAAAAAAIAAQQAAAEAQgAABEAAAQRCAAAAQgABBAAAAARCAAAE
QAABAAIAAAAAAAEEQgAAAEAAAQRAAAEEAgAAAEAAAAACAAAAAAABBEAAAQQCAAEEQgAAAEIAAAAA
AAAAAgAABAAAAQQAAAAAAgABAAAAAAQCAAEAAgABAEIAAAQCAAAAQAAABEIAAQAAAAEAQgABBAAA
AARAAAAEQgABBAAAAQBCAAEAQAABBEAAAIAAgCAAAIIggAACAAAAAAAAAAIggACAAAAAgCCAAIIg
gAAAAAAAACAAAIIAgAACAIAAggCAAAIggAAAIAAAgCAAAAIAgACCAIAAgAAAAAIggACCIIAAACAA
AAAAAACCAAAAACAAAIAAgAACIIAAgCAAAIAAAAACAAAAgiCAAAAAAACAAAAAAgCAAAAggACCIIAA
AgAAAAAgAAAAAAAAggCAAIAggAACIAAAAiCAAIAAAACCIIAAAACAAIAAAAACIIAAgiAAAIAAAACA
IIAAACAAAIIAgAACAIAAAiAAAIAggAAAAAAAgiCAAIIAAAAAAAAAACCAAIAgAAACAIAAggA=
"""


def _load_sp():
    raw = base64.b64decode(_SP_B64)
    if len(raw) != 2048:
        raise RuntimeError("повреждена встроенная таблица DES")
    return [int.from_bytes(raw[i:i + 4], "little") for i in range(0, 2048, 4)]


SPW = _load_sp()


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _rot(x: int, n: int) -> int:
    n &= 31
    return _u32((x >> n) | (x << (32 - n)))


def _load_block(b: bytes) -> Tuple[int, int]:
    return int.from_bytes(b[0:4], "little"), int.from_bytes(b[4:8], "little")


def _store_block(w0: int, w1: int) -> bytes:
    return w0.to_bytes(4, "little") + w1.to_bytes(4, "little")


def _initial_perm(sl: int, r8: int) -> Tuple[int, int]:
    r0 = (sl ^ (r8 >> 4)) & 0x0F0F0F0F
    r8 ^= _u32(r0 << 4)
    sl ^= r0
    r0 = (r8 ^ (sl >> 16)) & 0xFFFF
    sl ^= _u32(r0 << 16)
    r8 ^= r0
    r0 = (sl ^ (r8 >> 2)) & 0x33333333
    r8 ^= _u32(r0 << 2)
    sl ^= r0
    r0 = (r8 ^ (sl >> 8)) & 0x00FF00FF
    sl ^= _u32(r0 << 8)
    r8 ^= r0
    r0 = (sl ^ (r8 >> 1)) & 0x55555555
    r8 ^= _u32(r0 << 1)
    sl ^= r0
    return _rot(sl, 29), _rot(r8, 29)


def _undo_initial_perm(sl: int, r8: int) -> Tuple[int, int]:
    sl, r8 = _rot(sl, 3), _rot(r8, 3)
    r0 = (sl ^ (r8 >> 1)) & 0x55555555
    r8 ^= _u32(r0 << 1)
    sl ^= r0
    r0 = (r8 ^ (sl >> 8)) & 0x00FF00FF
    sl ^= _u32(r0 << 8)
    r8 ^= r0
    r0 = (sl ^ (r8 >> 2)) & 0x33333333
    r8 ^= _u32(r0 << 2)
    sl ^= r0
    r0 = (r8 ^ (sl >> 16)) & 0xFFFF
    sl ^= _u32(r0 << 16)
    r8 ^= r0
    r0 = (sl ^ (r8 >> 4)) & 0x0F0F0F0F
    r8 ^= _u32(r0 << 4)
    sl ^= r0
    return sl, r8


def _final_perm(r8: int, sl: int) -> Tuple[int, int]:
    r8 = _rot(r8, 3)
    sl = _rot(sl, 3)
    r2 = (r8 ^ (sl >> 1)) & 0x55555555
    sl ^= _u32(r2 << 1)
    r8 ^= r2
    r2 = (sl ^ (r8 >> 8)) & 0x00FF00FF
    r8 ^= _u32(r2 << 8)
    sl ^= r2
    r2 = (r8 ^ (sl >> 2)) & 0x33333333
    sl ^= _u32(r2 << 2)
    r8 ^= r2
    r2 = (sl ^ (r8 >> 16)) & 0xFFFF
    r8 ^= _u32(r2 << 16)
    sl ^= r2
    r2 = (r8 ^ (sl >> 4)) & 0x0F0F0F0F
    sl ^= _u32(r2 << 4)
    r8 ^= r2
    return r8, sl


def _F(half: int, k0: int, k1: int) -> int:
    x = _u32(half ^ k0)
    y = _rot(_u32(half ^ k1), 4)
    v = SPW[0 * 64 + ((x >> 2) & 0x3F)]
    v ^= SPW[2 * 64 + ((x >> 10) & 0x3F)]
    v ^= SPW[4 * 64 + ((x >> 18) & 0x3F)]
    v ^= SPW[6 * 64 + ((x >> 26) & 0x3F)]
    v ^= SPW[1 * 64 + ((y >> 2) & 0x3F)]
    v ^= SPW[3 * 64 + ((y >> 10) & 0x3F)]
    v ^= SPW[5 * 64 + ((y >> 18) & 0x3F)]
    v ^= SPW[7 * 64 + ((y >> 26) & 0x3F)]
    return _u32(v)


def des_block(block: bytes, encrypt: bool, key: bytes = KEY) -> bytes:
    if len(block) != 8:
        raise ValueError("блок DES должен быть 8 байт")
    if len(key) < 8:
        raise ValueError("ключ короче 8 байт")
    k0 = int.from_bytes(key[0:4], "little")
    k1 = int.from_bytes(key[4:8], "little")
    sl, r8 = _initial_perm(*_load_block(block))
    if encrypt:
        for r in range(16):
            a, b = (k0, k1) if r == 0 else (0, 0)
            if r % 2 == 0:
                r8 = _u32(r8 ^ _F(sl, a, b))
            else:
                sl = _u32(sl ^ _F(r8, a, b))
        return _store_block(*_final_perm(r8, sl))
    # decrypt: initial perm of ciphertext is L/R swapped vs post-round state
    sl, r8 = r8, sl
    for r in range(15, -1, -1):
        a, b = (k0, k1) if r == 0 else (0, 0)
        if r % 2 == 0:
            r8 = _u32(r8 ^ _F(sl, a, b))
        else:
            sl = _u32(sl ^ _F(r8, a, b))
    sl, r8 = _undo_initial_perm(sl, r8)
    return _store_block(sl, r8)


def prepare_password(password: str) -> bytes:
    """Как 0x10d95c: 16 байт, обрезка хвостовых пробелов/нулей, NUL после последнего символа."""
    src = password.encode("latin-1", "replace") + b"\x00" * 16
    buf = bytearray(src[:16])
    i = 15
    while i >= 0:
        if buf[i] in (0, 0x20):
            buf[i] = 0
            i -= 1
        else:
            break
    if i < 15:
        buf[i + 1] = 0
    return bytes(buf)


def encrypt_password(password: str) -> str:
    pt = prepare_password(password)
    ct = des_block(pt[0:8], True) + des_block(pt[8:16], True)
    hx = ct.hex()
    mac = hashlib.md5(hx.encode("ascii")).hexdigest()
    return hx + mac


def decrypt_hex(hex_str: str) -> Tuple[bytes, bool, str]:
    cleaned = "".join(ch for ch in hex_str.strip().lower() if ch in "0123456789abcdef")
    if len(cleaned) != 64:
        raise ValueError("ожидается 64 hex-символа (32 байта), получено %d" % len(cleaned))
    raw = bytes.fromhex(cleaned)
    c16, mac = raw[:16], raw[16:]
    expect = hashlib.md5(c16.hex().encode("ascii")).digest()
    mac_ok = expect == mac
    pt = des_block(c16[0:8], False) + des_block(c16[8:16], False)
    return pt, mac_ok, expect.hex()


def password_from_field(field: bytes) -> str:
    """Пароль как C-строка (до первого NUL) — так коммутатор сравнивает логин."""
    return field.split(b"\x00", 1)[0].decode("latin-1")


def vis(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "\\x%02x" % b for b in data)


def _selftest() -> int:
    known = {
        "EXAMPLEpass": "927dda26b5983e16a0a29d8fd760f0c244dc15830e040fdca05addafedd65617",
        "EXAMPLE123": "b76973fd3893765138579e75c65a6bd4f70f69c0f62f27b11721a6e8314e0436",
        "EXAMPLE1": "b76973fd38937651ddd17d6c045025abc6e06b247d2995f6fc4c4f26ba6b6e84",
        "DEMOuser1": "53a448fb1ddfc03370d333343210fe582eab637c88599c5e3b0dc8651f423b81",
        "DEMOpass1": "45a42a46c47256a070d333343210fe58b045d9e622e643c54a25de5f7299ad6c",
    }
    failed = 0
    for pw, hx in known.items():
        got = encrypt_password(pw)
        if got != hx:
            print("FAIL encrypt %r\n  got %s\n  exp %s" % (pw, got, hx))
            failed += 1
        pt, mac_ok, _ = decrypt_hex(hx)
        if not mac_ok or password_from_field(pt) != pw or encrypt_password(pw) != hx:
            # encrypt_password of a clean password must match only if the
            # 16-byte field had no leftover bytes after the NUL.
            if password_from_field(pt) != pw or not mac_ok:
                print("FAIL decrypt %r -> %r mac=%s" % (pw, pt, mac_ok))
                failed += 1
    # invertibility of the block cipher
    for block in (b"EXAMPLE1", b"\x00" * 8, b"abcdefgh"):
        if des_block(des_block(block, True), False) != block:
            print("FAIL invert", block)
            failed += 1
    # built-in synthetic default (DEMOpass1)
    pt, mac_ok, _ = decrypt_hex(DEFAULT_TARGET)
    if not mac_ok or password_from_field(pt) != "DEMOpass1":
        print("FAIL target", pt, mac_ok)
        failed += 1
    if failed:
        print("SELFTEST: %d error(s)" % failed)
        return 1
    print("SELFTEST: OK")
    return 0


def _print_result(hex_str: str, pt: bytes, mac_ok: bool) -> None:
    pw = password_from_field(pt)
    leftover = pt[len(pw) + 1:]  # after the first NUL
    leftover_nz = leftover.replace(b"\x00", b"")
    print("шифртекст : %s" % "".join(ch for ch in hex_str.strip().lower() if ch in "0123456789abcdef"))
    print("MD5-хвост : %s" % ("совпал" if mac_ok else "НЕ СОВПАЛ — это не PasswordEncryp этой схемы"))
    print("16 байт   : %s" % pt.hex())
    print("как есть  : %s" % vis(pt))
    print()
    print("Пароль (до первого нуля, так его видит логин):")
    print("  %s" % pw)
    if leftover_nz:
        print()
        print("В 16-байтном поле после нуля остался мусор от предыдущего")
        print("более длинного пароля (коммутатор не обнуляет весь буфер):")
        print("  %s" % vis(pt))
        print("На вход в логин это не влияет — сравнение идёт как с C-строкой.")


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Расшифровка PasswordEncryp коммутаторов Moxa ICS-G7852A (FW 5.x)."
    )
    parser.add_argument(
        "hex",
        nargs="?",
        help="64 hex-символа из поля PasswordEncryp_N= (по умолчанию — синтетический пример DEMOpass1)",
    )
    parser.add_argument(
        "--encrypt",
        metavar="PASSWORD",
        help="зашифровать пароль в формат конфигурации",
    )
    parser.add_argument("--selftest", action="store_true", help="проверить встроенные синтетические тест-векторы")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()
    if args.encrypt is not None:
        print(encrypt_password(args.encrypt))
        return 0

    target = args.hex or DEFAULT_TARGET
    try:
        pt, mac_ok, _ = decrypt_hex(target)
    except ValueError as exc:
        print("ошибка:", exc, file=sys.stderr)
        return 2
    _print_result(target, pt, mac_ok)
    return 0 if mac_ok else 3


if __name__ == "__main__":
    sys.exit(main())
