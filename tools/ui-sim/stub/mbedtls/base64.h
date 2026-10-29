#pragma once
#include <stddef.h>
static inline int mbedtls_base64_encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = 0;
    for (size_t i = 0; i < slen; i += 3) {
        unsigned v = src[i] << 16 | (i + 1 < slen ? src[i+1] << 8 : 0) | (i + 2 < slen ? src[i+2] : 0);
        if (n + 4 >= dlen) return -1;
        dst[n++] = T[(v >> 18) & 63]; dst[n++] = T[(v >> 12) & 63];
        dst[n++] = i + 1 < slen ? T[(v >> 6) & 63] : '=';
        dst[n++] = i + 2 < slen ? T[v & 63] : '=';
    }
    dst[n] = 0; *olen = n; return 0;
}
