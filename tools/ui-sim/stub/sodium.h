#pragma once
#include <string.h>
#include <stddef.h>
#define crypto_sign_ed25519_PUBLICKEYBYTES 32
#define crypto_sign_ed25519_SECRETKEYBYTES 64
#define crypto_sign_ed25519_SEEDBYTES 32
#define crypto_sign_ed25519_BYTES 64
inline void sodium_memzero(void *p, size_t n) { memset(p, 0, n); }
inline int sodium_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n) ? -1 : 0; }
