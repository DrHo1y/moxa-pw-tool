# moxa-pw-tool

Offline encrypt / decrypt tool for **Moxa ICS-G7852A** and **ICS-G7800A** series switches (firmware **5.x**, including 5.6, 5.9 and 5.12) `PasswordEncryp` configuration values. The algorithm is taken from the official firmware. Pure Python 3, no third-party packages.

🇷🇺 Russian version: [README.ru.md](README.ru.md)

## What it does

The `PasswordEncryp` field in a switch configuration is **not a hash** — it is reversible password encryption. This tool:

- decrypts a 64-character hex `PasswordEncryp` value back into the password;
- encrypts a given password into the same format (`--encrypt`);
- verifies the MD5 tail and reports any leftover "garbage" bytes in the 16-byte buffer.

The main file is `moxa_ics_password.py` in the repository root; on Windows run it via `run_ics.bat`.

The `legacy/` folder holds an earlier dictionary key-brute utility. It does **not** implement the firmware 5.x scheme and is kept only for historical reference — see `legacy/README.md`.

## Encryption scheme (firmware 5.x)

Verified against official ICS-G7852A / ICS-G7800A firmware versions **5.6**, **5.9** and **5.12**. The algorithm is identical in all three.

1. The password is placed in a **16-byte field**. Trailing spaces are stripped and the rest is padded with null bytes (`NUL`). At login the switch compares it as an ordinary C-string — up to the first null.
2. The field is split into two 8-byte blocks. Each block is encrypted with **DES** independently.
3. The key is hardcoded in the firmware as the ASCII string **`MOXA2DES`** (8 bytes). Important: the firmware copies those 8 bytes into a 128-byte key-schedule table **as-is**, without the standard DES key expansion. The remaining 120 bytes of the table are zero. That is why a stock DES/3DES from a crypto library does not reproduce this key.
4. The 16 bytes of ciphertext are written as lowercase hex (32 characters). The **MD5 of that hex string** is appended (another 32 hex characters). So the full `PasswordEncryp_N=` field is exactly **64 characters**.

When the password is changed, the switch does not always wipe all 16 bytes of the buffer: after the terminating null there may be leftover bytes from a longer previous password. This does not affect login, but the ciphertext may then not match a "clean" encryption of the same short string.

## Install and run (Windows)

1. Install [Python 3](https://www.python.org/downloads/). During setup check **Add Python to PATH**.
2. No extra packages are required.
3. Run by double-clicking `run_ics.bat`, or from a command prompt in the repository folder:

```bat
py moxa_ics_password.py --help
```

On Linux / macOS it is the same: `python3 moxa_ics_password.py`.

## Examples

Decrypt a value from the configuration (64 hex characters of a `PasswordEncryp_N=` field):

```bat
py moxa_ics_password.py cd280c9b2e88ac8cb11c724eba8d55a8c68e6b6eb9114353c3420dfc71829f66
```

Encrypt a password into the configuration format:

```bat
py moxa_ics_password.py --encrypt "ExamplePass1"
```

Expected output for this example:

```
cd280c9b2e88ac8cb11c724eba8d55a8c68e6b6eb9114353c3420dfc71829f66
```

Run the built-in self-test:

```bat
py moxa_ics_password.py --selftest
```

With no arguments the program uses a built-in example (handy for a quick check). For a real configuration always pass your own hex string explicitly.

## Background: CVE-2017-13699

In 2017, vulnerability [CVE-2017-13699](https://nvd.nist.gov/vuln/detail/CVE-2017-13699) (also CNVD-2017-37712) was published for Moxa EDS-G512E switches: configuration passwords were stored with reversible encryption and a fixed key baked into the firmware, so they could be recovered given the configuration file and knowledge of the scheme.

The tool in this repository targets a different line (ICS-G7800A / ICS-G7852A, firmware 5.x), but the class of problem is the same: `PasswordEncryp` is a cipher with a key embedded in the `.rom`, not a one-way hash. Knowing the algorithm and the key, a configuration value can be decrypted offline.

## Security and ethics

This code is meant **only to recover access to your own equipment** (or equipment you are authorized to administer): a forgotten password, inspecting your own configuration file, checking how the switch stores accounts.

Do not use it against other people's devices or configurations. The `PasswordEncryp` field is reversible — after you regain access, change the passwords and limit who holds copies of the configuration and firmware.

## Repository layout

```
moxa_ics_password.py   — working ICS-G78xxA FW 5.x encryptor / decryptor
run_ics.bat            — Windows launcher (finds py or python)
legacy/                — early dictionary brute-force (not the FW 5.x scheme)
LICENSE                — MIT
```

## License

MIT. See the `LICENSE` file.
