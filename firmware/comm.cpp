#include "comm.h"
#include "vault.h"
#include "ui.h"
#include "sshparse.h"
#include "fido2.h"
#include <stdarg.h>

HostComm Comm;

static int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hexDecode(const char *hex, uint8_t *out, size_t outMax) {
    size_t n = strlen(hex);
    if (n == 0 || (n & 1) || n / 2 > outMax) return 0;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexNibble(hex[2 * i]), lo = hexNibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n / 2;
}

static void hexEncode(const uint8_t *in, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = H[in[i] >> 4];
        out[2 * i + 1] = H[in[i] & 0x0F];
    }
    out[2 * n] = 0;
}

static bool validId(const char *id) {
    size_t n = strlen(id);
    if (n == 0 || n > 16) return false;
    for (size_t i = 0; i < n; i++) {
        if (!isalnum((unsigned char)id[i])) return false;
    }
    return true;
}

void HostComm::begin() {
    Serial.enableReboot(false);
    Serial.setRxBufferSize(4096);
    Serial.begin(115200);
    _rxLen = 0;
    _overflow = false;
    _state = IDLE;
}

void HostComm::reply(const char *id, const char *fmt, ...) {
    char buf[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    Serial.print(id);
    Serial.print(' ');
    Serial.println(buf);
}

void HostComm::finishPending(const char *text) {
    reply(_pendingId, "%s", text);
    sodium_memzero(_challenge, sizeof(_challenge));
    _challengeLen = 0;
    _state = IDLE;
    _pendingSlot = -1;
}

void HostComm::handleSign(const char *id, const char *hex) {
    if (_state != IDLE || Fido2.pending()) { reply(id, "ERR BUSY"); return; }
    if (!Vault.isPinSet())                 { reply(id, "ERR LOCKED"); return; }

    size_t len = hexDecode(hex, _challenge, sizeof(_challenge));
    if (len == 0) {
        sodium_memzero(_challenge, sizeof(_challenge));
        reply(id, "ERR INVALID_HEX");
        return;
    }

    strncpy(_pendingId, id, sizeof(_pendingId) - 1);
    _pendingId[sizeof(_pendingId) - 1] = 0;
    _challengeLen = len;

    if (!Vault.isUnlocked()) {
        _state = WAIT_UNLOCK;
        _waitDeadline = millis() + UNLOCK_WAIT_MS;
        UI.requestUnlock("Unlock to approve SSH login");
        return;
    }
    beginConfirm();
}

void HostComm::beginConfirm() {
    int slot = Vault.activeSlot();
    const VaultKey *k = Vault.keyAtSlot(slot);
    if (!k) { finishPending("ERR NO_ACTIVE_KEY"); return; }

    SignPrompt prompt;
    memset(&prompt, 0, sizeof(prompt));
    char hostFp[56];
    if (!sshParseUserauth(_challenge, _challengeLen, k->pubkey, prompt.target, sizeof(prompt.target),
                          hostFp, sizeof(hostFp))) {
        finishPending("ERR NOT_USERAUTH");
        return;
    }
    prompt.kind = PROMPT_SSH_LOGIN;
    strncpy(prompt.keyName, k->name, KEY_NAME_MAX_LEN);
    if (hostFp[0]) snprintf(prompt.detail, sizeof(prompt.detail), "Host %.30s...", hostFp);
    else snprintf(prompt.detail, sizeof(prompt.detail), "Host key not bound (old OpenSSH)");

    _pendingSlot = slot;
    _state = WAIT_CONFIRM;
    UI.requestSignConfirmation(prompt);
}

void HostComm::processLine(char *line) {
    char *id = strtok(line, " ");
    char *cmd = strtok(nullptr, " ");
    char *arg = strtok(nullptr, " ");
    char *extra = strtok(nullptr, " ");
    if (!id || !validId(id)) { Serial.println("? ERR BAD_ID"); return; }
    if (!cmd)                { reply(id, "ERR NO_COMMAND"); return; }
    if (extra)               { reply(id, "ERR EXTRA_ARGS"); return; }

    if (strcmp(cmd, "PING") == 0) {
        if (arg) { reply(id, "ERR EXTRA_ARGS"); return; }
        reply(id, "PONG");
    } else if (strcmp(cmd, "INFO") == 0) {
        if (arg) { reply(id, "ERR EXTRA_ARGS"); return; }
        reply(id, "INFO zeru-vault %s proto=2 hw=%d", FIRMWARE_VERSION, Vault.hardwareBound() ? 1 : 0);
    } else if (strcmp(cmd, "STATUS") == 0) {
        if (arg) { reply(id, "ERR EXTRA_ARGS"); return; }
        reply(id, Vault.isUnlocked() ? "STATUS UNLOCKED" : (Vault.isPinSet() ? "STATUS LOCKED" : "STATUS UNINITIALIZED"));
    } else if (strcmp(cmd, "GET_ACTIVE_PUBKEY") == 0) {
        if (arg) { reply(id, "ERR EXTRA_ARGS"); return; }
        char name[KEY_NAME_MAX_LEN + 1];
        uint8_t pub[32];
        if (!Vault.activePublic(name, pub)) {
            reply(id, Vault.isUnlocked() ? "ERR NO_ACTIVE_KEY" : "ERR LOCKED");
            return;
        }
        char hex[65];
        hexEncode(pub, 32, hex);
        reply(id, "PUBKEY %s %s", hex, name);
    } else if (strcmp(cmd, "SIGN") == 0) {
        if (!arg) { reply(id, "ERR NO_DATA"); return; }
        handleSign(id, arg);
    } else {
        reply(id, "ERR UNKNOWN_COMMAND");
    }
}

void HostComm::update() {
    if (_state == WAIT_UNLOCK) {
        if (Vault.isUnlocked()) {
            UI.clearUnlockRequest();
            beginConfirm();
        } else if (UI.takeUnlockDeclined()) {
            finishPending("ERR LOCKED");
        } else if ((int32_t)(millis() - _waitDeadline) >= 0) {
            UI.clearUnlockRequest();
            finishPending("ERR LOCKED");
        }
    } else if (_state == WAIT_CONFIRM) {
        if (!Vault.isUnlocked() || Vault.activeSlot() != _pendingSlot) {
            UI.cancelSignConfirmation();
            finishPending("ERR LOCKED");
        } else if (UI.signDecision() == SIGN_APPROVED) {
            UI.clearSignDecision();
            uint8_t sig[crypto_sign_ed25519_BYTES];
            if (Vault.sign(_pendingSlot, _challenge, _challengeLen, sig)) {
                char hex[2 * sizeof(sig) + 5];
                memcpy(hex, "SIG ", 4);
                hexEncode(sig, sizeof(sig), hex + 4);
                finishPending(hex);
            } else {
                finishPending("ERR SIGN_FAILED");
            }
        } else if (UI.signDecision() == SIGN_REJECTED) {
            UI.clearSignDecision();
            finishPending("ERR REJECTED");
        } else if (UI.signDecision() == SIGN_TIMEOUT) {
            UI.clearSignDecision();
            finishPending("ERR TIMEOUT");
        }
    }

    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\r') continue;
        if (c == '\n') {
            if (_overflow) {
                Serial.println("? ERR LINE_TOO_LONG");
            } else if (_rxLen > 0) {
                _rx[_rxLen] = 0;
                processLine(_rx);
            }
            _rxLen = 0;
            _overflow = false;
            continue;
        }
        if (_rxLen < RX_MAX) {
            _rx[_rxLen++] = c;
        } else {
            _overflow = true;
        }
    }
}
