#include "fido2.h"
#include "comm.h"
#include <USB.h>
#include <USBHID.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

Fido2Authenticator Fido2;

static const uint8_t FIDO_REPORT_DESC[] = {
    0x06, 0xD0, 0xF1,
    0x09, 0x01,
    0xA1, 0x01,
    0x09, 0x20,
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x81, 0x02,
    0x09, 0x21,
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x91, 0x02,
    0xC0
};

static constexpr uint8_t CTAPHID_PING      = 0x81;
static constexpr uint8_t CTAPHID_INIT      = 0x86;
static constexpr uint8_t CTAPHID_CBOR      = 0x90;
static constexpr uint8_t CTAPHID_CANCEL    = 0x91;
static constexpr uint8_t CTAPHID_KEEPALIVE = 0xBB;
static constexpr uint8_t CTAPHID_ERROR     = 0xBF;

static constexpr uint8_t CAPABILITY_CBOR = 0x04;
static constexpr uint8_t CAPABILITY_NMSG = 0x08;

static constexpr uint8_t KEEPALIVE_UPNEEDED   = 0x02;

static constexpr uint8_t ERR_INVALID_CMD  = 0x01;
static constexpr uint8_t ERR_INVALID_LEN  = 0x03;
static constexpr uint8_t ERR_INVALID_SEQ  = 0x04;
static constexpr uint8_t ERR_MSG_TIMEOUT  = 0x05;
static constexpr uint8_t ERR_CHANNEL_BUSY = 0x06;
static constexpr uint8_t ERR_INVALID_CHANNEL = 0x0B;

static constexpr uint8_t CTAP_CMD_MAKE_CREDENTIAL    = 0x01;
static constexpr uint8_t CTAP_CMD_GET_ASSERTION      = 0x02;
static constexpr uint8_t CTAP_CMD_GET_INFO           = 0x04;
static constexpr uint8_t CTAP_CMD_RESET              = 0x07;
static constexpr uint8_t CTAP_CMD_GET_NEXT_ASSERTION = 0x08;

static constexpr uint8_t CTAP2_OK                      = 0x00;
static constexpr uint8_t CTAP1_ERR_INVALID_COMMAND     = 0x01;
static constexpr uint8_t CTAP1_ERR_INVALID_PARAMETER   = 0x02;
static constexpr uint8_t CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11;
static constexpr uint8_t CTAP2_ERR_INVALID_CBOR        = 0x12;
static constexpr uint8_t CTAP2_ERR_MISSING_PARAMETER   = 0x14;
static constexpr uint8_t CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19;
static constexpr uint8_t CTAP2_ERR_UNSUPPORTED_ALG     = 0x26;
static constexpr uint8_t CTAP2_ERR_OPERATION_DENIED    = 0x27;
static constexpr uint8_t CTAP2_ERR_KEY_STORE_FULL      = 0x28;
static constexpr uint8_t CTAP2_ERR_UNSUPPORTED_OPTION  = 0x2B;
static constexpr uint8_t CTAP2_ERR_KEEPALIVE_CANCEL    = 0x2D;
static constexpr uint8_t CTAP2_ERR_NO_CREDENTIALS      = 0x2E;
static constexpr uint8_t CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F;
static constexpr uint8_t CTAP2_ERR_NOT_ALLOWED         = 0x30;
static constexpr uint8_t CTAP2_ERR_PIN_NOT_SET         = 0x35;

static constexpr uint8_t FLAG_UP = 0x01;
static constexpr uint8_t FLAG_UV = 0x04;
static constexpr uint8_t FLAG_AT = 0x40;

static constexpr int CBOR_MAX_DEPTH = 6;

static const uint8_t VAULT_AAGUID[16] = {
    0x3f, 0x6c, 0x2a, 0x1e, 0x8b, 0x4d, 0x4c, 0x7a,
    0x9e, 0x21, 0x5d, 0x0b, 0x7f, 0x9a, 0x6c, 0x13
};

static QueueHandle_t g_hidRxQueue = nullptr;
static USBHID g_usbHid;

class FidoHidDevice : public USBHIDDevice {
public:
    FidoHidDevice() {
        USB.productName("Zeru Vault");
        USB.manufacturerName("Zeru Security");
        USBHID::addDevice(this, sizeof(FIDO_REPORT_DESC));
    }
    uint16_t _onGetDescriptor(uint8_t *dst) override {
        memcpy(dst, FIDO_REPORT_DESC, sizeof(FIDO_REPORT_DESC));
        return sizeof(FIDO_REPORT_DESC);
    }
    void _onOutput(uint8_t reportId, const uint8_t *buf, uint16_t len) override {
        (void)reportId;
        if (len == 64 && g_hidRxQueue) {
            xQueueSend(g_hidRxQueue, buf, 0);
        }
    }
};

static FidoHidDevice g_fidoDev;

static uint32_t allocateCid() {
    uint32_t cid;
    do { secureRandom((uint8_t *)&cid, sizeof(cid)); } while (cid == 0 || cid == 0xFFFFFFFFu);
    return cid;
}

static int fidoRng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    secureRandom(out, len);
    return 0;
}

static size_t credInput(const uint8_t rpIdHash[32], const uint8_t nonce[32], uint8_t out[81]) {
    size_t n = 0;
    if (!Vault.fidoEpochIsLegacy()) {
        memcpy(out, Vault.fidoEpoch(), 16);
        n = 16;
    }
    memcpy(out + n, rpIdHash, 32); n += 32;
    memcpy(out + n, nonce, 32);    n += 32;
    return n;
}

static bool deriveCredMac(int slot, const uint8_t rpIdHash[32], const uint8_t nonce[32], uint8_t mac[32]) {
    uint8_t input[81];
    size_t n = credInput(rpIdHash, nonce, input);
    return Vault.deriveSlotHmac(slot, "FIDO2-CRED-MAC/v1", input, n, mac);
}

static bool credentialValid(int slot, const uint8_t rpIdHash[32], const uint8_t credId[64]) {
    uint8_t mac[32];
    bool ok = deriveCredMac(slot, rpIdHash, credId, mac) && sodium_memcmp(mac, credId + 32, 32) == 0;
    sodium_memzero(mac, sizeof(mac));
    return ok;
}

static bool deriveCredKeypair(int slot, const uint8_t rpIdHash[32], const uint8_t nonce[32],
                              mbedtls_ecp_keypair *kp, uint8_t pubX[32], uint8_t pubY[32]) {
    uint8_t input[81];
    size_t n = credInput(rpIdHash, nonce, input);

    uint8_t rawKey[32];
    bool ok = false;
    for (uint8_t ctr = 0; ctr < 8; ctr++) {
        input[n] = ctr;
        if (!Vault.deriveSlotHmac(slot, "FIDO2-CRED-KEY/v1", input, n + 1, rawKey)) break;
        if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, kp, rawKey, 32) == 0 &&
            mbedtls_ecp_keypair_calc_public(kp, fidoRng, nullptr) == 0) {
            ok = true;
            break;
        }
    }
    sodium_memzero(rawKey, sizeof(rawKey));
    if (!ok) return false;

    uint8_t pub65[65];
    size_t olen = 0;
    if (mbedtls_ecp_write_public_key(kp, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub65, sizeof(pub65)) != 0 ||
        olen != 65 || pub65[0] != 0x04) {
        return false;
    }
    if (pubX) memcpy(pubX, pub65 + 1, 32);
    if (pubY) memcpy(pubY, pub65 + 33, 32);
    return true;
}

static bool signWithCredKey(int slot, const uint8_t rpIdHash[32], const uint8_t nonce[32],
                            const uint8_t *msg, size_t msgLen, uint8_t *derSig, size_t *derSigLen) {
    uint8_t digest[32];
    mbedtls_sha256(msg, msgLen, digest, 0);

    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    bool ok = deriveCredKeypair(slot, rpIdHash, nonce, &kp, nullptr, nullptr) &&
              mbedtls_ecdsa_write_signature(&kp, MBEDTLS_MD_SHA256, digest, sizeof(digest),
                                            derSig, 80, derSigLen, fidoRng, nullptr) == 0;
    mbedtls_ecp_keypair_free(&kp);
    return ok;
}

static bool deriveEd25519CredKeypair(int slot, const uint8_t rpIdHash[32], const uint8_t nonce[32],
                                     uint8_t pub32[32], uint8_t sk64[64]) {
    uint8_t input[81];
    size_t n = credInput(rpIdHash, nonce, input);

    uint8_t seed[32];
    if (!Vault.deriveSlotHmac(slot, "FIDO2-ED25519-KEY/v1", input, n, seed)) {
        sodium_memzero(seed, sizeof(seed));
        return false;
    }
    uint8_t pk[32], sk[64];
    crypto_sign_ed25519_seed_keypair(pk, sk, seed);
    sodium_memzero(seed, sizeof(seed));
    if (pub32) memcpy(pub32, pk, 32);
    if (sk64)  memcpy(sk64, sk, 64);
    sodium_memzero(sk, sizeof(sk));
    return true;
}

static bool signWithEd25519CredKey(int slot, const uint8_t rpIdHash[32], const uint8_t nonce[32],
                                   const uint8_t *msg, size_t msgLen, uint8_t sig64[64]) {
    uint8_t sk[64];
    if (!deriveEd25519CredKeypair(slot, rpIdHash, nonce, nullptr, sk)) return false;
    unsigned long long sigLen = 0;
    int rc = crypto_sign_ed25519_detached(sig64, &sigLen, msg, msgLen, sk);
    sodium_memzero(sk, sizeof(sk));
    return rc == 0 && sigLen == 64;
}

static bool isEd25519Nonce(const uint8_t nonce[32]) {
    return nonce[0] == 0xED && nonce[1] == 0x08;
}

namespace {

struct CborReader {
    const uint8_t *p;
    size_t left;

    bool head(uint8_t &maj, uint64_t &val) {
        if (left < 1) return false;
        uint8_t b = *p++; left--;
        maj = b >> 5;
        uint8_t ai = b & 0x1F;
        if (ai < 24) { val = ai; return true; }
        if (ai == 24) { if (left < 1) return false; val = *p++; left--; return true; }
        if (ai == 25) { if (left < 2) return false; val = ((uint64_t)p[0] << 8) | p[1]; p += 2; left -= 2; return true; }
        if (ai == 26) {
            if (left < 4) return false;
            val = ((uint64_t)p[0] << 24) | ((uint64_t)p[1] << 16) | ((uint64_t)p[2] << 8) | p[3];
            p += 4; left -= 4; return true;
        }
        return false;
    }

    bool skip(int depth = 0) {
        if (depth > CBOR_MAX_DEPTH) return false;
        uint8_t maj; uint64_t val;
        if (!head(maj, val)) return false;
        switch (maj) {
            case 2: case 3:
                if (val > left) return false;
                p += val; left -= (size_t)val;
                return true;
            case 4:
                if (val > left) return false;
                for (uint64_t i = 0; i < val; i++) if (!skip(depth + 1)) return false;
                return true;
            case 5:
                if (val * 2 > left) return false;
                for (uint64_t i = 0; i < val * 2; i++) if (!skip(depth + 1)) return false;
                return true;
            case 6:
                return skip(depth + 1);
            default:
                return true;
        }
    }

    bool typed(uint8_t want, const uint8_t *&out, size_t &len) {
        uint8_t maj; uint64_t val;
        if (!head(maj, val) || maj != want || val > left) return false;
        out = p; len = (size_t)val;
        p += len; left -= len;
        return true;
    }
    bool bstr(const uint8_t *&out, size_t &len) { return typed(2, out, len); }
    bool tstr(const uint8_t *&out, size_t &len) { return typed(3, out, len); }

    bool container(uint8_t want, uint64_t &count) {
        uint8_t maj;
        if (!head(maj, count) || maj != want) return false;
        return want == 5 ? count * 2 <= left : count <= left;
    }

    bool boolean(bool &v) {
        uint8_t maj; uint64_t val;
        if (!head(maj, val) || maj != 7 || (val != 20 && val != 21)) return false;
        v = val == 21;
        return true;
    }

    bool keyIs(const uint8_t *k, size_t klen, const char *lit) {
        return klen == strlen(lit) && memcmp(k, lit, klen) == 0;
    }
};

struct CborWriter {
    uint8_t *buf;
    size_t max;
    size_t len = 0;

    void put(uint8_t b) { if (len < max) buf[len++] = b; }
    void putBytes(const void *d, size_t n) {
        if (len + n <= max) { memcpy(buf + len, d, n); len += n; }
    }
    void head(uint8_t maj, uint32_t val) {
        uint8_t m = maj << 5;
        if (val < 24)        { put(m | (uint8_t)val); }
        else if (val <= 0xFF){ put(m | 24); put((uint8_t)val); }
        else                 { put(m | 25); put((uint8_t)(val >> 8)); put((uint8_t)val); }
    }
    void uint(uint32_t v)  { head(0, v); }
    void nint(int32_t v)   { head(1, (uint32_t)(-1 - v)); }
    void bstr(const uint8_t *d, size_t n) { head(2, n); putBytes(d, n); }
    void tstr(const char *s) { size_t n = strlen(s); head(3, n); putBytes(s, n); }
    void array(uint32_t n) { head(4, n); }
    void map(uint32_t n)   { head(5, n); }
    void boolean(bool b)   { put(b ? 0xF5 : 0xF4); }
};

static void copyPrintable(const uint8_t *src, size_t n, char *dst, size_t dstMax, bool keepTail) {
    size_t cap = dstMax - 1;
    size_t start = 0, prefix = 0;
    if (n > cap && keepTail) {
        start = n - (cap - 2);
        dst[0] = '.'; dst[1] = '.';
        prefix = 2;
    }
    size_t copy = n - start;
    if (copy > cap - prefix) copy = cap - prefix;
    for (size_t c = 0; c < copy; c++) {
        uint8_t ch = src[start + c];
        dst[prefix + c] = (ch >= 0x20 && ch < 0x7F) ? (char)ch : '?';
    }
    dst[prefix + copy] = 0;
}

static bool rpIdAcceptable(const uint8_t *v, size_t n) {
    if (n == 0 || n > 253) return false;
    for (size_t i = 0; i < n; i++) {
        if (v[i] <= 0x20 || v[i] >= 0x7F) return false;
    }
    return true;
}

static int findCredInList(CborReader r, int slot, const uint8_t rpIdHash[32], uint8_t matchedNonce[32], bool &ok) {
    ok = false;
    uint64_t arrLen;
    if (!r.container(4, arrLen)) return 0;
    int found = 0;
    for (uint64_t i = 0; i < arrLen; i++) {
        uint64_t pairs;
        if (!r.container(5, pairs)) return 0;
        const uint8_t *idPtr = nullptr; size_t idLen = 0;
        for (uint64_t j = 0; j < pairs; j++) {
            const uint8_t *k; size_t klen;
            if (!r.tstr(k, klen)) return 0;
            if (r.keyIs(k, klen, "id")) {
                if (!r.bstr(idPtr, idLen)) return 0;
            } else if (!r.skip()) {
                return 0;
            }
        }
        if (!found && idPtr && idLen == 64 && credentialValid(slot, rpIdHash, idPtr)) {
            memcpy(matchedNonce, idPtr, 32);
            found = 1;
        }
    }
    ok = true;
    return found;
}

}

void Fido2Authenticator::begin() {
    g_hidRxQueue = xQueueCreate(16, 64);
    g_usbHid.begin();
    USB.productName("Zeru Vault");
    USB.manufacturerName("Zeru Security");
    USB.begin();
}

void Fido2Authenticator::sendResponse(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len) {
    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = (uint8_t)(cid >> 24);
    pkt[1] = (uint8_t)(cid >> 16);
    pkt[2] = (uint8_t)(cid >> 8);
    pkt[3] = (uint8_t)cid;
    pkt[4] = cmd | 0x80;
    pkt[5] = (uint8_t)(len >> 8);
    pkt[6] = (uint8_t)len;

    size_t chunk = len > 57 ? 57 : len;
    if (chunk > 0 && data) memcpy(pkt + 7, data, chunk);
    g_usbHid.SendReport(0, pkt, 64, 100);

    size_t sent = chunk;
    uint8_t seq = 0;
    while (sent < len) {
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = (uint8_t)(cid >> 24);
        pkt[1] = (uint8_t)(cid >> 16);
        pkt[2] = (uint8_t)(cid >> 8);
        pkt[3] = (uint8_t)cid;
        pkt[4] = seq++ & 0x7F;
        chunk = (len - sent) > 59 ? 59 : (len - sent);
        memcpy(pkt + 5, data + sent, chunk);
        g_usbHid.SendReport(0, pkt, 64, 100);
        sent += chunk;
    }
}

void Fido2Authenticator::sendCborStatus(uint32_t cid, uint8_t status) {
    sendResponse(cid, CTAPHID_CBOR, &status, 1);
}

void Fido2Authenticator::sendError(uint32_t cid, uint8_t err) {
    sendResponse(cid, CTAPHID_ERROR, &err, 1);
}

void Fido2Authenticator::sendKeepalive(uint32_t cid, uint8_t status) {
    sendResponse(cid, CTAPHID_KEEPALIVE, &status, 1);
}

void Fido2Authenticator::endWait(uint8_t status) {
    uint32_t cid = _waitCid;
    if (_waitState == WAIT_UNLOCK) UI.clearUnlockRequest();
    else UI.cancelSignConfirmation();
    _waitState = WAIT_NONE;
    _candidateCount = 0;
    sendCborStatus(cid, status);
}

void Fido2Authenticator::onPacket(const uint8_t pkt[64]) {
    uint32_t cid = ((uint32_t)pkt[0] << 24) | ((uint32_t)pkt[1] << 16) |
                   ((uint32_t)pkt[2] << 8)  | pkt[3];
    if (cid == 0) {
        sendError(cid, ERR_INVALID_CHANNEL);
        return;
    }

    if (pkt[4] & 0x80) {
        uint8_t cmd = pkt[4];
        uint16_t bcnt = ((uint16_t)pkt[5] << 8) | pkt[6];

        if (cmd == CTAPHID_INIT) {
            if (bcnt != 8) { sendError(cid, ERR_INVALID_LEN); return; }
            uint32_t newCid = (cid == 0xFFFFFFFFu) ? allocateCid() : cid;
            if (_waitState != WAIT_NONE && _waitCid == cid) {
                if (_waitState == WAIT_UNLOCK) UI.clearUnlockRequest();
                else UI.cancelSignConfirmation();
                _waitState = WAIT_NONE;
            }
            if (_rxCid == cid) _rxCid = 0;
            uint8_t resp[17];
            memcpy(resp, pkt + 7, 8);
            resp[8]  = (uint8_t)(newCid >> 24);
            resp[9]  = (uint8_t)(newCid >> 16);
            resp[10] = (uint8_t)(newCid >> 8);
            resp[11] = (uint8_t)newCid;
            resp[12] = 2;
            resp[13] = 2;
            resp[14] = 0;
            resp[15] = 0;
            resp[16] = CAPABILITY_CBOR | CAPABILITY_NMSG;
            sendResponse(cid, CTAPHID_INIT, resp, sizeof(resp));
            return;
        }

        if (cid == 0xFFFFFFFFu) {
            sendError(cid, ERR_INVALID_CHANNEL);
            return;
        }

        if (cmd == CTAPHID_CANCEL) {
            if (_waitState != WAIT_NONE && _waitCid == cid) endWait(CTAP2_ERR_KEEPALIVE_CANCEL);
            return;
        }

        if (_rxCid != 0 && _rxCid != cid) {
            sendError(cid, ERR_CHANNEL_BUSY);
            return;
        }
        if (_waitState != WAIT_NONE || Comm.signPending()) {
            sendError(cid, ERR_CHANNEL_BUSY);
            return;
        }
        if (bcnt > sizeof(_rxBuf)) {
            sendError(cid, ERR_INVALID_LEN);
            return;
        }

        _rxCid = cid;
        _rxCmd = cmd;
        _rxExpected = bcnt;
        _rxSeq = 0;
        _rxDeadline = millis() + 1500;
        uint16_t copy = bcnt > 57 ? 57 : bcnt;
        memcpy(_rxBuf, pkt + 7, copy);
        _rxOffset = copy;

        if (_rxOffset >= _rxExpected) {
            _rxCid = 0;
            handleMessage(cid, cmd, _rxBuf, _rxExpected);
        }
    } else {
        if (_rxCid == 0 || cid == 0xFFFFFFFFu) return;
        if (cid != _rxCid) {
            sendError(cid, ERR_CHANNEL_BUSY);
            return;
        }
        uint8_t seq = pkt[4];
        if (seq != _rxSeq++) {
            _rxCid = 0;
            sendError(cid, ERR_INVALID_SEQ);
            return;
        }
        uint16_t rem = _rxExpected - _rxOffset;
        uint16_t copy = rem > 59 ? 59 : rem;
        memcpy(_rxBuf + _rxOffset, pkt + 5, copy);
        _rxOffset += copy;
        _rxDeadline = millis() + 1500;

        if (_rxOffset >= _rxExpected) {
            uint8_t cmd = _rxCmd;
            uint16_t total = _rxExpected;
            _rxCid = 0;
            handleMessage(cid, cmd, _rxBuf, total);
        }
    }
}

void Fido2Authenticator::handleMessage(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len) {
    switch (cmd) {
        case CTAPHID_PING:
            sendResponse(cid, CTAPHID_PING, data, len);
            break;
        case CTAPHID_CBOR:
            handleCbor(cid, data, len);
            break;
        default:
            sendError(cid, ERR_INVALID_CMD);
            break;
    }
}

void Fido2Authenticator::handleCbor(uint32_t cid, const uint8_t *data, size_t len) {
    if (len < 1) { sendCborStatus(cid, CTAP1_ERR_INVALID_COMMAND); return; }
    uint8_t ctapCmd = data[0];
    const uint8_t *body = data + 1;
    size_t bodyLen = len - 1;

    switch (ctapCmd) {
        case CTAP_CMD_GET_INFO:
            handleGetInfo(cid);
            return;
        case CTAP_CMD_GET_NEXT_ASSERTION:
            sendCborStatus(cid, CTAP2_ERR_NOT_ALLOWED);
            return;
        case CTAP_CMD_MAKE_CREDENTIAL:
        case CTAP_CMD_GET_ASSERTION:
        case CTAP_CMD_RESET:
            break;
        default:
            sendCborStatus(cid, CTAP1_ERR_INVALID_COMMAND);
            return;
    }

    if (!Vault.isPinSet()) {
        UI.notify(MSG_WARN, "Set up the vault first", "Create a PIN on the device");
        sendCborStatus(cid, CTAP2_ERR_OPERATION_DENIED);
        return;
    }
    if (!Vault.isUnlocked()) {
        memcpy(_reqBuf, body, bodyLen);
        _reqLen = bodyLen;
        _reqCmd = ctapCmd;
        _waitState = WAIT_UNLOCK;
        _waitCid = cid;
        _waitDeadline = millis() + UNLOCK_WAIT_MS;
        _lastKeepalive = millis();
        sendKeepalive(cid, KEEPALIVE_UPNEEDED);
        UI.requestUnlock(ctapCmd == CTAP_CMD_RESET ? "Unlock to reset passkeys" : "Unlock to use your passkey");
        return;
    }
    dispatchCtap(cid, ctapCmd, body, bodyLen);
}

void Fido2Authenticator::dispatchCtap(uint32_t cid, uint8_t ctapCmd, const uint8_t *body, size_t len) {
    switch (ctapCmd) {
        case CTAP_CMD_MAKE_CREDENTIAL: handleMakeCredential(cid, body, len); break;
        case CTAP_CMD_GET_ASSERTION:   handleGetAssertion(cid, body, len); break;
        case CTAP_CMD_RESET:           handleReset(cid); break;
        default:                       sendCborStatus(cid, CTAP1_ERR_INVALID_COMMAND); break;
    }
}

void Fido2Authenticator::handleGetInfo(uint32_t cid) {
    uint8_t out[128];
    out[0] = CTAP2_OK;
    CborWriter w{out + 1, sizeof(out) - 1, 0};

    w.map(4);
    w.uint(1); w.array(1); w.tstr("FIDO_2_0");
    w.uint(3); w.bstr(VAULT_AAGUID, 16);
    w.uint(4); w.map(4);
    w.tstr("rk"); w.boolean(true);
    w.tstr("up"); w.boolean(true);
    w.tstr("uv"); w.boolean(true);
    w.tstr("plat"); w.boolean(false);
    w.uint(5); w.uint(sizeof(_rxBuf));

    sendResponse(cid, CTAPHID_CBOR, out, 1 + w.len);
}

void Fido2Authenticator::handleMakeCredential(uint32_t cid, const uint8_t *cbor, size_t len) {
    int slot = Vault.activeSlot();
    const VaultKey *activeKey = Vault.keyAtSlot(slot);
    if (!activeKey) {
        UI.notify(MSG_WARN, "No active key", "Create a key on the device");
        sendCborStatus(cid, CTAP2_ERR_OPERATION_DENIED);
        return;
    }

    CborReader r{cbor, len};
    uint64_t mapLen;
    if (!r.container(5, mapLen)) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }

    bool hasCdh = false, hasRp = false, hasUser = false, hasAlgs = false, hasPinAuth = false;
    int8_t firstSupportedAlg = 0;
    _rpId[0] = 0;
    _userIdLen = 0;
    _userName[0] = 0;
    _excludeMatched = false;
    _makeResident = false;
    _uvRequested = false;
    CborReader excludeReader{nullptr, 0};
    char displayName[USER_NAME_MAX_LEN + 1] = {0};

    for (uint64_t i = 0; i < mapLen; i++) {
        uint8_t km; uint64_t key;
        if (!r.head(km, key) || km != 0) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }

        if (key == 1) {
            const uint8_t *d; size_t n;
            if (!r.bstr(d, n) || n != 32) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
            memcpy(_clientDataHash, d, 32);
            hasCdh = true;
        } else if (key == 2) {
            uint64_t pairs;
            if (!r.container(5, pairs)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
            for (uint64_t j = 0; j < pairs; j++) {
                const uint8_t *k; size_t klen;
                if (!r.tstr(k, klen)) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
                if (r.keyIs(k, klen, "id")) {
                    const uint8_t *v; size_t vlen;
                    if (!r.tstr(v, vlen)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
                    if (!rpIdAcceptable(v, vlen)) { sendCborStatus(cid, CTAP1_ERR_INVALID_PARAMETER); return; }
                    mbedtls_sha256(v, vlen, _rpIdHash, 0);
                    copyPrintable(v, vlen, _rpId, sizeof(_rpId), true);
                    hasRp = true;
                } else if (!r.skip()) {
                    sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return;
                }
            }
        } else if (key == 3) {
            uint64_t pairs;
            if (!r.container(5, pairs)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
            for (uint64_t j = 0; j < pairs; j++) {
                const uint8_t *k; size_t klen;
                if (!r.tstr(k, klen)) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
                const uint8_t *v; size_t vlen;
                if (r.keyIs(k, klen, "id")) {
                    if (!r.bstr(v, vlen) || vlen == 0 || vlen > USER_ID_MAX_LEN) {
                        sendCborStatus(cid, CTAP1_ERR_INVALID_PARAMETER);
                        return;
                    }
                    memcpy(_userId, v, vlen);
                    _userIdLen = (uint8_t)vlen;
                    hasUser = true;
                } else if (r.keyIs(k, klen, "name")) {
                    if (!r.tstr(v, vlen)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
                    copyPrintable(v, vlen, _userName, sizeof(_userName), false);
                } else if (r.keyIs(k, klen, "displayName")) {
                    if (!r.tstr(v, vlen)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
                    copyPrintable(v, vlen, displayName, sizeof(displayName), false);
                } else if (!r.skip()) {
                    sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return;
                }
            }
        } else if (key == 4) {
            uint64_t alen;
            if (!r.container(4, alen)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
            hasAlgs = true;
            for (uint64_t j = 0; j < alen; j++) {
                uint64_t ppairs;
                if (!r.container(5, ppairs)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
                bool isPublicKey = false;
                int8_t alg = 0;
                for (uint64_t m = 0; m < ppairs; m++) {
                    const uint8_t *k; size_t klen;
                    if (!r.tstr(k, klen)) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
                    if (r.keyIs(k, klen, "alg")) {
                        uint8_t vm; uint64_t vval;
                        if (!r.head(vm, vval)) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
                        if (vm == 1 && vval == 6) alg = -7;
                        else if (vm == 1 && vval == 7) alg = -8;
                    } else if (r.keyIs(k, klen, "type")) {
                        const uint8_t *t; size_t tlen;
                        if (!r.tstr(t, tlen)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
                        isPublicKey = r.keyIs(t, tlen, "public-key");
                    } else if (!r.skip()) {
                        sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return;
                    }
                }
                if (isPublicKey && alg != 0 && firstSupportedAlg == 0) firstSupportedAlg = alg;
            }
        } else if (key == 5) {
            excludeReader = r;
            if (!r.skip()) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
        } else if (key == 7) {
            uint64_t opairs;
            if (!r.container(5, opairs)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
            for (uint64_t j = 0; j < opairs; j++) {
                const uint8_t *k; size_t klen;
                bool v;
                if (!r.tstr(k, klen) || !r.boolean(v)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
                if (r.keyIs(k, klen, "rk")) _makeResident = v;
                else if (r.keyIs(k, klen, "uv")) _uvRequested = v;
            }
        } else if (key == 8) {
            hasPinAuth = true;
            if (!r.skip()) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
        } else {
            if (!r.skip()) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
        }
    }

    if (hasPinAuth) { sendCborStatus(cid, CTAP2_ERR_PIN_NOT_SET); return; }
    if (!hasCdh || !hasRp || !hasUser || !hasAlgs) {
        sendCborStatus(cid, CTAP2_ERR_MISSING_PARAMETER);
        return;
    }
    if (firstSupportedAlg == 0) {
        sendCborStatus(cid, CTAP2_ERR_UNSUPPORTED_ALG);
        return;
    }
    _credAlg = firstSupportedAlg;
    if (!_userName[0] && displayName[0]) memcpy(_userName, displayName, sizeof(_userName));

    if (excludeReader.p) {
        uint8_t dummyNonce[32];
        bool ok;
        _excludeMatched = findCredInList(excludeReader, slot, _rpIdHash, dummyNonce, ok) > 0;
        if (!ok) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
    }
    if (_makeResident && !_excludeMatched &&
        !Vault.passkeyCapacityFor(slot, _rpIdHash, _userId, _userIdLen)) {
        UI.notify(MSG_WARN, "Passkey storage full", "Delete one in Settings");
        sendCborStatus(cid, CTAP2_ERR_KEY_STORE_FULL);
        return;
    }

    SignPrompt prompt;
    memset(&prompt, 0, sizeof(prompt));
    bool ssh = strncmp(_rpId, "ssh:", 4) == 0;
    prompt.kind = _excludeMatched ? PROMPT_ALREADY_REGISTERED : (ssh ? PROMPT_SK_CREATE : PROMPT_PASSKEY_CREATE);
    strncpy(prompt.keyName, activeKey->name, KEY_NAME_MAX_LEN);
    strncpy(prompt.target, _rpId, RP_ID_MAX_LEN);
    if (_excludeMatched) {
        snprintf(prompt.detail, sizeof(prompt.detail), "This key is already registered here");
    } else if (ssh) {
        snprintf(prompt.detail, sizeof(prompt.detail), "New OpenSSH security key (ssh-keygen)");
    } else if (_userName[0] && !ssh) {
        strncpy(prompt.accounts[0], _userName, USER_NAME_MAX_LEN);
        prompt.accountCount = 1;
    } else if (!_makeResident && !ssh) {
        snprintf(prompt.detail, sizeof(prompt.detail), "Security key (not stored on device)");
    }

    _waitState = WAIT_MAKE_CRED;
    _waitCid = cid;
    _waitSlot = slot;
    _lastKeepalive = millis();
    UI.requestSignConfirmation(prompt);
}

void Fido2Authenticator::hintOtherSlots(const uint8_t *allowList, size_t allowLen) {
    for (int s = 0; s < MAX_KEYS; s++) {
        if (s == Vault.activeSlot()) continue;
        const VaultKey *k = Vault.keyAtSlot(s);
        if (!k) continue;
        bool match = false;
        if (allowList) {
            uint8_t nonce[32];
            bool ok;
            CborReader r{allowList, allowLen};
            match = findCredInList(r, s, _rpIdHash, nonce, ok) > 0;
        } else {
            const Passkey *found[1];
            match = Vault.findPasskeys(s, _rpIdHash, found, 1) > 0;
        }
        if (match) {
            char sub[48];
            snprintf(sub, sizeof(sub), "Activate key %s to use it", k->name);
            UI.notify(MSG_WARN, "Passkey on other key", sub);
            return;
        }
    }
    UI.notify(MSG_WARN, "No passkey for this site", _rpId);
}

void Fido2Authenticator::handleGetAssertion(uint32_t cid, const uint8_t *cbor, size_t len) {
    int slot = Vault.activeSlot();
    const VaultKey *activeKey = Vault.keyAtSlot(slot);
    if (!activeKey) {
        sendCborStatus(cid, CTAP2_ERR_NO_CREDENTIALS);
        return;
    }

    CborReader r{cbor, len};
    uint64_t mapLen;
    if (!r.container(5, mapLen)) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }

    bool hasRp = false, hasCdh = false, up = true, hasPinAuth = false;
    _uvRequested = false;
    const uint8_t *allowStart = nullptr;
    size_t allowLen = 0;

    for (uint64_t i = 0; i < mapLen; i++) {
        uint8_t km; uint64_t key;
        if (!r.head(km, key) || km != 0) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }

        if (key == 1) {
            const uint8_t *v; size_t vlen;
            if (!r.tstr(v, vlen)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
            if (!rpIdAcceptable(v, vlen)) { sendCborStatus(cid, CTAP1_ERR_INVALID_PARAMETER); return; }
            mbedtls_sha256(v, vlen, _rpIdHash, 0);
            copyPrintable(v, vlen, _rpId, sizeof(_rpId), true);
            hasRp = true;
        } else if (key == 2) {
            const uint8_t *d; size_t n;
            if (!r.bstr(d, n) || n != 32) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
            memcpy(_clientDataHash, d, 32);
            hasCdh = true;
        } else if (key == 3) {
            allowStart = r.p;
            if (!r.skip()) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
            allowLen = r.p - allowStart;
        } else if (key == 5) {
            uint64_t opairs;
            if (!r.container(5, opairs)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
            for (uint64_t j = 0; j < opairs; j++) {
                const uint8_t *k; size_t klen;
                bool v;
                if (!r.tstr(k, klen) || !r.boolean(v)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
                if (r.keyIs(k, klen, "up")) up = v;
                else if (r.keyIs(k, klen, "uv")) _uvRequested = v;
                else if (r.keyIs(k, klen, "rk")) { sendCborStatus(cid, CTAP2_ERR_UNSUPPORTED_OPTION); return; }
            }
        } else if (key == 6) {
            hasPinAuth = true;
            if (!r.skip()) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
        } else {
            if (!r.skip()) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
        }
    }

    if (hasPinAuth) { sendCborStatus(cid, CTAP2_ERR_PIN_NOT_SET); return; }
    if (!hasRp || !hasCdh) {
        sendCborStatus(cid, CTAP2_ERR_MISSING_PARAMETER);
        return;
    }

    bool hasAllowList = false;
    if (allowStart) {
        CborReader check{allowStart, allowLen};
        uint64_t alen = 0;
        if (!check.container(4, alen)) { sendCborStatus(cid, CTAP2_ERR_CBOR_UNEXPECTED_TYPE); return; }
        hasAllowList = alen > 0;
    }

    _candidateCount = 0;
    _fromAllowList = hasAllowList;
    if (hasAllowList) {
        bool ok;
        CborReader list{allowStart, allowLen};
        if (findCredInList(list, slot, _rpIdHash, _allowNonce, ok) == 0) {
            if (!ok) { sendCborStatus(cid, CTAP2_ERR_INVALID_CBOR); return; }
            if (up) hintOtherSlots(allowStart, allowLen);
            sendCborStatus(cid, CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
        const Passkey *pk = Vault.findPasskeyByNonce(slot, _rpIdHash, _allowNonce);
        _candidates[0] = pk;
        _candidateCount = 1;
    } else {
        _candidateCount = Vault.findPasskeys(slot, _rpIdHash, _candidates, PROMPT_MAX_ACCOUNTS);
        if (_candidateCount == 0) {
            if (up) hintOtherSlots(nullptr, 0);
            sendCborStatus(cid, CTAP2_ERR_NO_CREDENTIALS);
            return;
        }
    }

    _waitCid = cid;
    _waitSlot = slot;
    if (!up) {
        finishGetAssertion(0, false);
        return;
    }

    SignPrompt prompt;
    memset(&prompt, 0, sizeof(prompt));
    prompt.kind = strncmp(_rpId, "ssh:", 4) == 0 ? PROMPT_SK_USE : PROMPT_PASSKEY_USE;
    strncpy(prompt.keyName, activeKey->name, KEY_NAME_MAX_LEN);
    strncpy(prompt.target, _rpId, RP_ID_MAX_LEN);
    for (int i = 0; i < _candidateCount; i++) {
        if (_candidates[i]) strncpy(prompt.accounts[i], _candidates[i]->userName, USER_NAME_MAX_LEN);
    }
    prompt.accountCount = (_candidateCount == 1 && !(_candidates[0] && _candidates[0]->userName[0])) ? 0 : _candidateCount;
    if (prompt.kind == PROMPT_SK_USE && prompt.accountCount == 0) {
        snprintf(prompt.detail, sizeof(prompt.detail), "OpenSSH security key login");
    }

    _waitState = WAIT_GET_ASSERT;
    _lastKeepalive = millis();
    UI.requestSignConfirmation(prompt);
}

void Fido2Authenticator::handleReset(uint32_t cid) {
    const VaultKey *k = Vault.keyAtSlot(Vault.activeSlot());
    SignPrompt prompt;
    memset(&prompt, 0, sizeof(prompt));
    prompt.kind = PROMPT_FIDO_RESET;
    strncpy(prompt.keyName, k ? k->name : "-", KEY_NAME_MAX_LEN);
    snprintf(prompt.target, sizeof(prompt.target), "All passkeys");
    snprintf(prompt.detail, sizeof(prompt.detail), "Every passkey & ssh-sk key stops working");

    _waitState = WAIT_RESET;
    _waitCid = cid;
    _waitSlot = Vault.activeSlot();
    _lastKeepalive = millis();
    UI.requestSignConfirmation(prompt);
}

void Fido2Authenticator::finishMakeCredential() {
    uint32_t cid = _waitCid;
    int slot = _waitSlot;
    _waitState = WAIT_NONE;

    if (_excludeMatched) {
        sendCborStatus(cid, CTAP2_ERR_CREDENTIAL_EXCLUDED);
        return;
    }

    uint8_t nonce[32], mac[32], pubX[32], pubY[32];
    secureRandom(nonce, sizeof(nonce));
    if (_credAlg == -8) {
        nonce[0] = 0xED;
        nonce[1] = 0x08;
    } else {
        nonce[0] = 0xEC;
        nonce[1] = 0x07;
    }
    if (!deriveCredMac(slot, _rpIdHash, nonce, mac)) {
        sendCborStatus(cid, CTAP2_ERR_OPERATION_DENIED);
        return;
    }

    uint8_t coseKey[80];
    CborWriter cw{coseKey, sizeof(coseKey), 0};
    if (_credAlg == -8) {
        if (!deriveEd25519CredKeypair(slot, _rpIdHash, nonce, pubX, nullptr)) {
            sendCborStatus(cid, CTAP2_ERR_OPERATION_DENIED);
            return;
        }
        cw.map(4);
        cw.uint(1); cw.uint(1);
        cw.uint(3); cw.nint(-8);
        cw.nint(-1); cw.uint(6);
        cw.nint(-2); cw.bstr(pubX, 32);
    } else {
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        bool ok = deriveCredKeypair(slot, _rpIdHash, nonce, &kp, pubX, pubY);
        mbedtls_ecp_keypair_free(&kp);
        if (!ok) {
            sendCborStatus(cid, CTAP2_ERR_OPERATION_DENIED);
            return;
        }
        cw.map(5);
        cw.uint(1); cw.uint(2);
        cw.uint(3); cw.nint(-7);
        cw.nint(-1); cw.uint(1);
        cw.nint(-2); cw.bstr(pubX, 32);
        cw.nint(-3); cw.bstr(pubY, 32);
    }

    if (_makeResident) {
        Passkey pk;
        memset(&pk, 0, sizeof(pk));
        pk.slot = (uint8_t)slot;
        pk.userIdLen = _userIdLen;
        memcpy(pk.rpIdHash, _rpIdHash, 32);
        memcpy(pk.nonce, nonce, 32);
        memcpy(pk.userId, _userId, _userIdLen);
        strncpy(pk.rpId, _rpId, RP_ID_MAX_LEN);
        strncpy(pk.userName, _userName, USER_NAME_MAX_LEN);
        StoreResult sr = Vault.storePasskey(pk);
        sodium_memzero(&pk, sizeof(pk));
        if (sr != STORE_OK) {
            sendCborStatus(cid, sr == STORE_FULL ? CTAP2_ERR_KEY_STORE_FULL : CTAP2_ERR_OPERATION_DENIED);
            return;
        }
    }

    uint8_t authData[37 + 18 + 64 + 80];
    size_t adLen = 0;
    memcpy(authData + adLen, _rpIdHash, 32); adLen += 32;
    authData[adLen++] = FLAG_UP | FLAG_AT | (_uvRequested ? FLAG_UV : 0);
    uint32_t cnt = Vault.nextSignCounter();
    authData[adLen++] = (uint8_t)(cnt >> 24);
    authData[adLen++] = (uint8_t)(cnt >> 16);
    authData[adLen++] = (uint8_t)(cnt >> 8);
    authData[adLen++] = (uint8_t)cnt;
    memcpy(authData + adLen, VAULT_AAGUID, 16); adLen += 16;
    authData[adLen++] = 0x00;
    authData[adLen++] = 64;
    memcpy(authData + adLen, nonce, 32); adLen += 32;
    memcpy(authData + adLen, mac, 32);   adLen += 32;
    memcpy(authData + adLen, coseKey, cw.len); adLen += cw.len;

    uint8_t toSign[sizeof(authData) + 32];
    memcpy(toSign, authData, adLen);
    memcpy(toSign + adLen, _clientDataHash, 32);

    uint8_t derSig[80];
    size_t sigLen = 0;
    bool signedOk = _credAlg == -8
        ? (sigLen = 64, signWithEd25519CredKey(slot, _rpIdHash, nonce, toSign, adLen + 32, derSig))
        : signWithCredKey(slot, _rpIdHash, nonce, toSign, adLen + 32, derSig, &sigLen);
    if (!signedOk) {
        sendCborStatus(cid, CTAP2_ERR_OPERATION_DENIED);
        return;
    }

    uint8_t resp[384];
    resp[0] = CTAP2_OK;
    CborWriter rw{resp + 1, sizeof(resp) - 1, 0};
    rw.map(3);
    rw.uint(1); rw.tstr("packed");
    rw.uint(2); rw.bstr(authData, adLen);
    rw.uint(3); rw.map(2);
    rw.tstr("alg"); rw.nint(_credAlg);
    rw.tstr("sig"); rw.bstr(derSig, sigLen);

    sendResponse(cid, CTAPHID_CBOR, resp, 1 + rw.len);
}

void Fido2Authenticator::finishGetAssertion(int account, bool userPresent) {
    uint32_t cid = _waitCid;
    int slot = _waitSlot;
    _waitState = WAIT_NONE;

    if (account < 0 || account >= _candidateCount) account = 0;
    const Passkey *pk = _candidates[account];
    uint8_t nonce[32];
    memcpy(nonce, _fromAllowList ? _allowNonce : pk->nonce, 32);
    _candidateCount = 0;

    uint8_t mac[32];
    if (!deriveCredMac(slot, _rpIdHash, nonce, mac)) {
        sendCborStatus(cid, CTAP2_ERR_OPERATION_DENIED);
        return;
    }
    uint8_t credId[64];
    memcpy(credId, nonce, 32);
    memcpy(credId + 32, mac, 32);

    bool uv = userPresent && _uvRequested;
    uint8_t toSign[37 + 32];
    memcpy(toSign, _rpIdHash, 32);
    toSign[32] = (userPresent ? FLAG_UP : 0) | (uv ? FLAG_UV : 0);
    uint32_t cnt = Vault.nextSignCounter();
    toSign[33] = (uint8_t)(cnt >> 24);
    toSign[34] = (uint8_t)(cnt >> 16);
    toSign[35] = (uint8_t)(cnt >> 8);
    toSign[36] = (uint8_t)cnt;
    memcpy(toSign + 37, _clientDataHash, 32);

    uint8_t derSig[80];
    size_t sigLen = 0;
    bool signedOk = isEd25519Nonce(nonce)
        ? (sigLen = 64, signWithEd25519CredKey(slot, _rpIdHash, nonce, toSign, sizeof(toSign), derSig))
        : signWithCredKey(slot, _rpIdHash, nonce, toSign, sizeof(toSign), derSig, &sigLen);
    if (!signedOk) {
        sendCborStatus(cid, CTAP2_ERR_OPERATION_DENIED);
        return;
    }

    bool includeUser = pk && pk->userIdLen > 0;
    bool includeName = includeUser && uv && pk->userName[0];

    uint8_t resp[384];
    resp[0] = CTAP2_OK;
    CborWriter rw{resp + 1, sizeof(resp) - 1, 0};
    rw.map(includeUser ? 4 : 3);
    rw.uint(1); rw.map(2);
    rw.tstr("id"); rw.bstr(credId, sizeof(credId));
    rw.tstr("type"); rw.tstr("public-key");
    rw.uint(2); rw.bstr(toSign, 37);
    rw.uint(3); rw.bstr(derSig, sigLen);
    if (includeUser) {
        rw.uint(4);
        rw.map(includeName ? 2 : 1);
        rw.tstr("id"); rw.bstr(pk->userId, pk->userIdLen);
        if (includeName) { rw.tstr("name"); rw.tstr(pk->userName); }
    }

    sendResponse(cid, CTAPHID_CBOR, resp, 1 + rw.len);
}

void Fido2Authenticator::update() {
    uint32_t now = millis();

    if (_rxCid != 0 && (int32_t)(now - _rxDeadline) >= 0) {
        uint32_t cid = _rxCid;
        _rxCid = 0;
        sendError(cid, ERR_MSG_TIMEOUT);
    }

    if (_waitState == WAIT_UNLOCK) {
        if (Vault.isUnlocked()) {
            UI.clearUnlockRequest();
            _waitState = WAIT_NONE;
            dispatchCtap(_waitCid, _reqCmd, _reqBuf, _reqLen);
            sodium_memzero(_reqBuf, sizeof(_reqBuf));
        } else if (UI.takeUnlockDeclined()) {
            endWait(CTAP2_ERR_OPERATION_DENIED);
        } else if ((int32_t)(now - _waitDeadline) >= 0) {
            endWait(CTAP2_ERR_USER_ACTION_TIMEOUT);
        } else if (now - _lastKeepalive >= 100) {
            _lastKeepalive = now;
            sendKeepalive(_waitCid, KEEPALIVE_UPNEEDED);
        }
    } else if (_waitState != WAIT_NONE) {
        if (!Vault.isUnlocked() || Vault.activeSlot() != _waitSlot) {
            endWait(CTAP2_ERR_OPERATION_DENIED);
        } else if (UI.signDecision() == SIGN_APPROVED) {
            UI.clearSignDecision();
            if (_waitState == WAIT_MAKE_CRED) {
                finishMakeCredential();
            } else if (_waitState == WAIT_GET_ASSERT) {
                finishGetAssertion(UI.signAccount(), true);
            } else {
                uint32_t cid = _waitCid;
                _waitState = WAIT_NONE;
                sendCborStatus(cid, Vault.resetFido() ? CTAP2_OK : CTAP2_ERR_OPERATION_DENIED);
            }
        } else if (UI.signDecision() == SIGN_REJECTED) {
            UI.clearSignDecision();
            endWait(CTAP2_ERR_OPERATION_DENIED);
        } else if (UI.signDecision() == SIGN_TIMEOUT) {
            UI.clearSignDecision();
            endWait(CTAP2_ERR_USER_ACTION_TIMEOUT);
        } else if (now - _lastKeepalive >= 100) {
            _lastKeepalive = now;
            sendKeepalive(_waitCid, KEEPALIVE_UPNEEDED);
        }
    }

    uint8_t pkt[64];
    while (g_hidRxQueue && xQueueReceive(g_hidRxQueue, pkt, 0) == pdTRUE) {
        onPacket(pkt);
    }
}
