# Third-party notices

[🇧🇷 Português](THIRD-PARTY-NOTICES.md) · 🇺🇸 English

Zeru Vault's code is licensed under the [MIT License](LICENSE). The **compiled firmware** also contains third-party components, each under its own license:

| Component | Used for | License |
| :--- | :--- | :--- |
| [arduino-esp32](https://github.com/espressif/arduino-esp32) 3.3.x | Arduino core for the ESP32-S3 | LGPL-2.1-only |
| [ESP-IDF](https://github.com/espressif/esp-idf) (bundled in the core) | System, drivers, NVS, eFuse, HMAC | Apache-2.0 |
| FreeRTOS (in ESP-IDF) | Real-time operating system | MIT |
| Mbed TLS (in ESP-IDF) | AES-GCM, PBKDF2, SHA-256, ECDSA P-256 | Apache-2.0 |
| libsodium (in ESP-IDF) | Ed25519, constant-time comparison, zeroization | ISC |
| TinyUSB (in the core) | USB HID (FIDO2) and CDC serial | MIT |
| [GFX Library for Arduino](https://github.com/moononournation/Arduino_GFX) 1.6.x | Display drawing | BSD (derived from Adafruit GFX) |
| Fonts in `firmware/fonts/` | On-screen text | **GPL-3.0-or-later** with font exception (GNU FreeFont), see [`firmware/fonts/LICENSE.md`](firmware/fonts/LICENSE.md) |

## What this implies

- **Source code:** you may use, modify and redistribute this repository's code under the MIT License.
- **Firmware binary:** because of the GNU FreeFont fonts, treat a compiled `.bin` as distributed under **GPL-3.0-or-later**: when you distribute it, also offer the corresponding source code and the GPL text. Since the whole project is open and can be rebuilt with `make build`, this also satisfies the LGPL-2.1 requirement of the arduino-esp32 core (letting users rebuild the firmware with a modified version of the library).
- **For a binary with permissive licenses only**, replace the fonts with SIL OFL, Apache-2.0 or Bitstream Vera/DejaVu fonts converted with Adafruit's `fontconvert`.
- The Python agent (`agent/`) uses only the Python standard library. The screenshot renderer (`tools/ui-sim/`) uses Pillow on the developer's machine only; none of it ships in the firmware.

This is a good-faith description, not legal advice.
