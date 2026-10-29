#include "sshparse.h"
#include <string.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>

namespace {

struct Reader {
    const uint8_t *p;
    size_t left;

    bool u8(uint8_t &v) {
        if (left < 1) return false;
        v = *p++; left--;
        return true;
    }
    bool str(const uint8_t *&d, uint32_t &n) {
        if (left < 4) return false;
        n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
        p += 4; left -= 4;
        if (n > left) return false;
        d = p; p += n; left -= n;
        return true;
    }
    bool strEq(const char *lit) {
        const uint8_t *d; uint32_t n;
        return str(d, n) && n == strlen(lit) && memcmp(d, lit, n) == 0;
    }
};

}

bool sshParseUserauth(const uint8_t *data, size_t len,
                      const uint8_t expectedPub[32],
                      char *user, size_t userMax,
                      char *hostFp, size_t hostFpMax) {
    if (!data || !user || userMax < 2 || !hostFp || hostFpMax < 52) return false;
    hostFp[0] = 0;
    Reader r{data, len};
    const uint8_t *d; uint32_t n; uint8_t b;

    if (!r.str(d, n) || n < 20 || n > 64) return false;
    if (!r.u8(b) || b != 50) return false;

    const uint8_t *u; uint32_t ulen;
    if (!r.str(u, ulen) || ulen == 0 || ulen >= userMax) return false;

    if (!r.strEq("ssh-connection")) return false;

    const uint8_t *method; uint32_t methodLen;
    if (!r.str(method, methodLen)) return false;
    bool hostbound = false;
    if (methodLen == 9 && memcmp(method, "publickey", 9) == 0) {
        hostbound = false;
    } else if (methodLen == 35 && memcmp(method, "publickey-hostbound-v00@openssh.com", 35) == 0) {
        hostbound = true;
    } else {
        return false;
    }

    if (!r.u8(b) || b != 1) return false;
    if (!r.strEq("ssh-ed25519")) return false;

    const uint8_t *blob; uint32_t blobLen;
    if (!r.str(blob, blobLen)) return false;
    Reader k{blob, blobLen};
    const uint8_t *pk; uint32_t pkLen;
    if (!k.strEq("ssh-ed25519") || !k.str(pk, pkLen) || pkLen != 32 || k.left != 0) return false;
    if (memcmp(pk, expectedPub, 32) != 0) return false;

    const uint8_t *hostKey = nullptr; uint32_t hostKeyLen = 0;
    if (hostbound) {
        if (!r.str(hostKey, hostKeyLen) || hostKeyLen < 16) return false;
        Reader hk{hostKey, hostKeyLen};
        const uint8_t *type; uint32_t typeLen;
        if (!hk.str(type, typeLen) || typeLen == 0) return false;
    }

    if (r.left != 0) return false;

    if (hostKey) {
        uint8_t digest[32];
        mbedtls_sha256(hostKey, hostKeyLen, digest, 0);
        unsigned char b64[48];
        size_t olen = 0;
        mbedtls_base64_encode(b64, sizeof(b64), &olen, digest, sizeof(digest));
        while (olen > 0 && b64[olen - 1] == '=') olen--;
        b64[olen] = 0;
        snprintf(hostFp, hostFpMax, "SHA256:%s", (const char *)b64);
    }

    for (uint32_t i = 0; i < ulen; i++) {
        uint8_t c = u[i];
        user[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
    }
    user[ulen] = 0;
    return true;
}
