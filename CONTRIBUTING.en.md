# Contributing to Zeru Vault

[🇧🇷 Português](CONTRIBUTING.md) · 🇺🇸 English

Thank you for your interest in contributing to **Zeru Vault**!

## Code Standards

1. **Self-Documenting Code:** Keep identifiers, types, constants (`constexpr`), and control flow clear and self-explanatory without inline comments.
2. **Memory Safety & Zeroization:**
   - Never put plaintext key material on the heap. (Wrapped / encrypted blobs and public data may use it.)
   - Always zeroize temporary buffers (`seed`, `kek`, `dek`, `pin`, private scalars, HMAC keys) using `sodium_memzero()` on every return path.
   - Use constant-time comparison (`sodium_memcmp` or `mbedtls_ct_memcmp`) when verifying MACs, tags, or secrets.
3. **Zero Host Dependencies:** `agent/ssh_vault_agent.py` must run on standard Python 3 using only the standard library.
4. **Warnings are errors in review:** `make build` compiles with `--warnings all`; keep it at zero warnings in project files.

## Building & Verifying

```bash
make build                                        # compile firmware
make flash                                        # backs up NVS, flashes app only (hold BOOT, tap RST when asked)
make test                                         # end-to-end SSH signature on the device
python3 -I agent/ssh_vault_agent.py test --hostbound   # also exercises the host-key display
make screenshots                                  # re-render docs/images/*.png from the UI code
```

Never flash `build/firmware.ino.merged.bin` to a device that holds a vault: it covers the whole flash, including the NVS partition, and erases every key.

Any change to `firmware/ui.cpp` must be followed by `make screenshots`; review the images and commit them with the change so the README always matches the firmware.

## Documentation

The main documentation is in **Portuguese (PT-BR)**; English is the secondary language (`*.en.md` files). When you change a document, update both versions. The device UI and the code stay in English.

## Licenses

The project code is MIT. Before adding a dependency, font or image, check its license and record it in [THIRD-PARTY-NOTICES.en.md](THIRD-PARTY-NOTICES.en.md) (and the Portuguese version). Prefer permissive licenses (MIT, BSD, Apache-2.0, ISC, SIL OFL for fonts).

## Security invariants

Changes must keep these properties:

- Nothing received from the host may reset the auto-lock timer, postpone the auto-lock, or approve a request.
- Approval screens start with *Reject* selected, ignore input for `SIGN_ARM_MS`, discard gestures that started before the prompt, and never auto-repeat.
- FIDO2 `UP`/`UV` flags must reflect what actually happened on the device.
- The serial protocol only signs data accepted by `sshParseUserauth()` for the active key.
- Anything that deletes secrets must call `compact()` so stale ciphertext is physically erased.
- The USB CDC auto-reboot into the bootloader stays disabled (`Serial.enableReboot(false)`).
