# Security Policy

[🇧🇷 Português](SECURITY.md) · 🇺🇸 English

## Threat Model

**Zeru Vault** is an open-source hardware security key (FIDO2/CTAP2 + SSH agent) for the ESP32-S3 with an on-device display and two physical buttons.

| Attacker | Goal | Defended by |
| :--- | :--- | :--- |
| Malware on the host (same user) | Silent signatures / logins | Every signature needs the user to move from the preselected *Reject* to *Approve* and confirm with both buttons, on a screen that names the site / SSH user / host key. `up:false` assertions are answered with the **UP and UV flags cleared**. |
| Malware on the host | Keep the vault unlocked forever | Auto-lock counts **only physical button activity** (15 min) plus a hard 12 h session cap. Host traffic never resets it, and a pending request does not postpone it. |
| Malware on the host | Re-flash a backdoored firmware over USB | USB CDC auto-reset (1200 bps touch / DTR-RTS sequence) is **disabled**; entering download mode needs the BOOT button. |
| Malware on the host | Approve through a well-timed request | Approval is armed 700 ms after the prompt appears, gestures that began earlier are discarded, *Reject* is preselected and button auto-repeat is disabled on approval and delete screens. |
| Malicious website / SSH server | Trick the user into approving | The request type comes from the protocol, never guessed from text. Long RP IDs are trimmed from the left so the registrable domain stays visible. Hostbound SSH requests show the server host-key fingerprint. |
| Shoulder surfer / camera | Learn the PIN from button presses | The PIN drum starts at a random digit for every digit entered. |
| Thief with the device (no PIN) | Guess the PIN | 10 attempts, exponential cooldown after 3, counter persisted **before** key derivation (fail closed if the write fails), full flash wipe on the 10th failure. |
| Thief who dumps the SPI flash | Offline PIN brute force | The key-encryption key is `HMAC_eFuse(PBKDF2(PIN))`. The HMAC key lives in a read-protected eFuse block that only the on-chip HMAC peripheral can use, so a flash image alone is useless. |

### Residual risks (be explicit)

- **No Secure Boot / Flash Encryption by default.** An attacker with physical access *and* time can enter download mode with the BOOT button, flash their own firmware and use the chip's HMAC peripheral to brute-force the PIN **on the device**, bypassing the attempt counter. The calibrated PBKDF2 (~0.9 s per guess) makes a 6-digit PIN cost ~10 days and an 8-digit PIN ~3 years of continuous attack. Use 8 digits for high-value keys, or apply the optional hardening below.
- **No backup.** Keys are generated on the chip and can never be exported. Register a second authenticator (or keep recovery codes) on every account.
- **Built-in user verification is session based.** The FIDO2 `UV` flag means "the PIN was entered on the device in this session" (at most 12 h, locked after 15 min without a button press), like other authenticators with on-device PIN entry. There is no CTAP `clientPIN`.
- **Factory reset needs no PIN.** Anyone holding the device can erase it (denial of service only; no data is revealed). This mirrors the FIDO reset behaviour of commercial keys.
- **USB VID/PID** `303a:1001` is Espressif's development identifier, and the USB serial number is the chip MAC (a stable identifier). Production units should use their own PID.

## Cryptographic Architecture (vault format v3)

1. **Data Encryption Key (DEK).** A random 256-bit DEK encrypts every SSH seed and every passkey record with AES-256-GCM (random 96-bit IV, AAD = format version + slot/index + key name + public key).
2. **PIN wrapping.** `KEK = HMAC_eFuse("ZV3/KEK" ‖ salt ‖ PBKDF2-HMAC-SHA256(PIN, salt, N))`, with `N` calibrated on the chip to ~0.9 s (bounded to 20 000 – 1 000 000 and validated on every unlock). The DEK is wrapped with AES-256-GCM under the KEK; the GCM tag is the PIN verifier. Salt, `N`, the hardware flag and the wrapped DEK are stored as a single NVS blob, so changing the PIN is atomic.
3. **Hardware binding.** On first setup (or the first unlock after upgrading from v2) the firmware burns a random 256-bit key into a free eFuse key block with purpose `HMAC_UP` and read protection. This is **irreversible** and uses one of the six key blocks; the board stays usable for other projects.
4. **Secure deletion.** Deleting a key or passkey, changing the PIN, resetting passkeys or migrating from v2 rewrites the whole NVS partition through a power-fail-safe snapshot kept briefly in the unused FAT partition, physically erasing stale ciphertext. Factory reset erases the NVS partition and the snapshot area.
5. **FIDO2 credentials.** Credential IDs are `nonce ‖ HMAC(seed, epoch ‖ rpIdHash ‖ nonce)`, verified in constant time before any prompt. Keys are derived per RP from the active slot's seed (`ES256` or `EdDSA`, honouring the RP's preference order). Discoverable credentials are stored **only** when `rk=true`, encrypted under the DEK. `authenticatorReset` and *Settings → Reset passkeys* rotate the epoch, revoking every credential. CTAPHID channel IDs are random.
6. **SSH (no signing oracle).** The serial interface only signs well-formed RFC 4252 `SSH_MSG_USERAUTH_REQUEST` (or `publickey-hostbound-v00@openssh.com`) blobs for `ssh-ed25519` that match the active key.

## Optional hardening: Secure Boot v2 + Flash Encryption

The default build does **not** enable these features, on purpose: both are permanent decisions written into the chip's eFuses (one-time-programmable bits that can never be cleared). They are documented here as a future option for a dedicated, "production" device.

| Feature | What it burns | What changes afterwards | Main risk |
| :--- | :--- | :--- | :--- |
| **Secure Boot v2** | The digest of *your* RSA-3072 signing public key(s) (the ESP32-S3 supports RSA-PSS only), and the enable bit | The ROM only boots a bootloader signed by you, and the bootloader only runs firmware signed by you. You can still flash anything (even another project) **if you sign it**. | **Losing the private signing key** means the board can never run new firmware. The chip accepts up to 3 key digests, so keep a spare key and a backup. |
| **Flash Encryption (release mode)** | A chip-generated AES-XTS key that nobody can read, and the enable counter | Flash contents are encrypted with a per-chip key; plain serial flashing is refused. Updates go through the signed / OTA path. | A power cut during the **first** boot (when the flash is encrypted in place) or a firmware without an update path can leave the board unusable. |
| `DIS_USB_JTAG`, `DIS_PAD_JTAG`, `ENABLE_SECURITY_DOWNLOAD` (or `DIS_DOWNLOAD_MODE`) | Disable debug ports and restrict / disable the ROM download mode | No JTAG debugging; esptool can no longer read the flash (or cannot connect at all). | Development becomes much harder; mistakes cannot be undone. |

With these enabled, the on-chip PIN brute force described in *Residual risks* is no longer possible, because an attacker cannot run their own code on the chip.

Requirements and advice:

1. The Arduino core ships a prebuilt bootloader without Secure Boot support, so the firmware must be built with **ESP-IDF** (Arduino as an ESP-IDF component) and `CONFIG_SECURE_BOOT_V2_ENABLED`, `CONFIG_SECURE_FLASH_ENC_ENABLED` (release mode) and NVS encryption (HMAC-based scheme) enabled.
2. Generate the signing key offline, store it with a backup (e.g. in a password manager), and keep at least one revocable spare key digest.
3. Rehearse the whole procedure on a **second, spare board** first. Keep that spare as your development board.
4. Use an 8-digit PIN anyway.

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities. Report them privately through the repository's GitHub Security Advisories tab (`Security` -> `Report a vulnerability`) with:

- Affected component (`firmware/vault.cpp`, `firmware/fido2.cpp`, `firmware/sshparse.cpp`, `agent/ssh_vault_agent.py`, etc.)
- Proof-of-concept steps or reproduction payload
- Impact assessment
