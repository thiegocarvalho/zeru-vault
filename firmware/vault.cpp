#include "vault.h"
#include <Preferences.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <esp_random.h>
#include <esp_hmac.h>
#include <esp_efuse.h>
#include <esp_partition.h>
#include <nvs_flash.h>
#include "bootloader_random.h"

VaultManager Vault;
static Preferences prefs;

static const char *NVS_NS     = "ssh-vault";
static const char *K_FORMAT   = "fmt";
static const char *K_AUTH     = "auth";
static const char *K_FAILS    = "pin_fails";
static const char *K_KEYS     = "keys";
static const char *K_ACTIVE   = "active";
static const char *K_EPOCH    = "fepoch";
static const char *K_COUNTER  = "sig_cnt";

static const char *K_LEGACY_SALT     = "pin_salt";
static const char *K_LEGACY_VERIFIER = "pin_check";
static const char *K_LEGACY_KEYS     = "keys_data";
static const char *NS_LEGACY_RK      = "fido2rk";
static constexpr uint8_t  LEGACY_FORMAT_VERSION = 2;
static constexpr uint32_t LEGACY_PBKDF2_ITERATIONS = 20000;
static constexpr int      LEGACY_RESIDENT_KEYS = 16;

static constexpr uint32_t KDF_TARGET_MS = 900;
static constexpr uint32_t KDF_MIN_ITER  = 20000;
static constexpr uint32_t KDF_MAX_ITER  = 1000000;
static constexpr uint32_t KDF_PROBE_ITER = 2000;

static constexpr uint32_t SNAP_MAGIC = 0x5A565333;
static constexpr size_t   SNAP_SIZE  = 16384;

struct __attribute__((packed)) AuthBlob {
    uint8_t  salt[16];
    uint32_t iterations;
    uint8_t  hw;
    uint8_t  iv[12];
    uint8_t  wrappedDek[32];
    uint8_t  tag[16];
};

struct __attribute__((packed)) LegacyPasskeyRecord {
    uint8_t used;
    uint8_t slot;
    uint8_t userIdLen;
    uint8_t rpIdHash[32];
    uint8_t nonce[32];
    uint8_t mac[32];
    uint8_t userId[64];
    char    userName[33];
};

struct SnapHeader {
    uint32_t magic;
    uint32_t len;
    uint8_t  sha[32];
};

void secureRandom(uint8_t *buf, size_t len) {
    bootloader_random_enable();
    esp_fill_random(buf, len);
    bootloader_random_disable();
}

static bool gcmSeal(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aadLen,
                    const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[16]) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, n, iv, 12, aad, aadLen, pt, ct, 16, tag);
    }
    mbedtls_gcm_free(&gcm);
    return ret == 0;
}

static bool gcmOpen(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aadLen,
                    const uint8_t *ct, size_t n, const uint8_t tag[16], uint8_t *pt) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, n, iv, 12, aad, aadLen, tag, 16, ct, pt);
    }
    mbedtls_gcm_free(&gcm);
    if (ret != 0) sodium_memzero(pt, n);
    return ret == 0;
}

static void hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen, uint8_t out[32]) {
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, keyLen, msg, msgLen, out);
}

static bool hardwareKey(bool provision, hmac_key_id_t &id) {
    esp_efuse_block_t block;
    if (!esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &block)) {
        if (!provision) return false;
        block = esp_efuse_find_unused_key_block();
        if (block == EFUSE_BLK_KEY_MAX) return false;
        uint8_t key[32];
        secureRandom(key, sizeof(key));
        esp_err_t err = esp_efuse_write_key(block, ESP_EFUSE_KEY_PURPOSE_HMAC_UP, key, sizeof(key));
        sodium_memzero(key, sizeof(key));
        if (err != ESP_OK) return false;
        if (!esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &block)) return false;
    }
    id = (hmac_key_id_t)(HMAC_KEY0 + (block - EFUSE_BLK_KEY0));
    uint8_t probe[32];
    bool ok = esp_hmac_calculate(id, "ZV3/probe", 9, probe) == ESP_OK;
    sodium_memzero(probe, sizeof(probe));
    return ok;
}

static void wrapAad(const AuthBlob &a, uint8_t aad[4 + 1 + 16 + 4 + 1], size_t *len) {
    size_t n = 0;
    memcpy(aad + n, "ZVDK", 4); n += 4;
    aad[n++] = VAULT_FORMAT_VERSION;
    memcpy(aad + n, a.salt, 16); n += 16;
    memcpy(aad + n, &a.iterations, 4); n += 4;
    aad[n++] = a.hw;
    *len = n;
}

static bool authBlobSane(const AuthBlob &a) {
    return a.iterations >= KDF_MIN_ITER && a.iterations <= KDF_MAX_ITER && a.hw <= 1;
}

static void passkeyKeyName(int idx, char out[8]) {
    snprintf(out, 8, "pk%02d", idx);
}

bool VaultManager::deriveKek(const char *pin, const uint8_t salt[16], uint32_t iterations, uint8_t kek[32]) {
    uint8_t stretched[32];
    if (mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)pin, strlen(pin),
                                      salt, 16, iterations, sizeof(stretched), stretched) != 0) {
        return false;
    }
    bool ok;
    if (_hwBound) {
        hmac_key_id_t id;
        uint8_t msg[7 + 16 + 32];
        memcpy(msg, "ZV3/KEK", 7);
        memcpy(msg + 7, salt, 16);
        memcpy(msg + 23, stretched, 32);
        ok = hardwareKey(false, id) && esp_hmac_calculate(id, msg, sizeof(msg), kek) == ESP_OK;
        sodium_memzero(msg, sizeof(msg));
    } else {
        static const char label[] = "ZV3/KEK/software";
        hmacSha256(stretched, sizeof(stretched), (const uint8_t *)label, sizeof(label) - 1, kek);
        ok = true;
    }
    sodium_memzero(stretched, sizeof(stretched));
    if (!ok) sodium_memzero(kek, 32);
    return ok;
}

uint32_t VaultManager::calibrateIterations() {
    uint8_t salt[16] = {0}, out[32];
    uint32_t t0 = millis();
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)"probe", 5,
                                  salt, sizeof(salt), KDF_PROBE_ITER, sizeof(out), out);
    uint32_t elapsed = millis() - t0;
    if (elapsed == 0) elapsed = 1;
    uint64_t iter = (uint64_t)KDF_PROBE_ITER * KDF_TARGET_MS / elapsed;
    if (iter < KDF_MIN_ITER) iter = KDF_MIN_ITER;
    if (iter > KDF_MAX_ITER) iter = KDF_MAX_ITER;
    return (uint32_t)iter;
}

bool VaultManager::writeAuth(const char *pin) {
    hmac_key_id_t id;
    _hwBound = hardwareKey(true, id);

    AuthBlob a;
    memset(&a, 0, sizeof(a));
    secureRandom(a.salt, sizeof(a.salt));
    a.iterations = calibrateIterations();
    a.hw = _hwBound ? 1 : 0;
    secureRandom(a.iv, sizeof(a.iv));

    uint8_t kek[32];
    if (!deriveKek(pin, a.salt, a.iterations, kek)) return false;
    uint8_t aad[26];
    size_t aadLen;
    wrapAad(a, aad, &aadLen);
    bool ok = gcmSeal(kek, a.iv, aad, aadLen, _dek, sizeof(_dek), a.wrappedDek, a.tag);
    sodium_memzero(kek, sizeof(kek));
    return ok && prefs.putBytes(K_AUTH, &a, sizeof(a)) == sizeof(a);
}

bool VaultManager::begin() {
    if (sodium_init() < 0) return false;
    prefs.begin(NVS_NS, false);
    restoreSnapshotIfPresent();
    sodium_memzero(_keys, sizeof(_keys));
    sodium_memzero(_passkeys, sizeof(_passkeys));
    memset(_passkeyUsed, 0, sizeof(_passkeyUsed));
    _unlocked = false;
    _activeSlot = -1;
    _lastActivity = millis();
    loadMeta();

    armThrottle(prefs.getUChar(K_FAILS, 0));
    return true;
}

void VaultManager::loadMeta() {
    memset(_fidoEpoch, 0, sizeof(_fidoEpoch));
    if (prefs.getBytesLength(K_EPOCH) == sizeof(_fidoEpoch)) {
        prefs.getBytes(K_EPOCH, _fidoEpoch, sizeof(_fidoEpoch));
    }
    AuthBlob a;
    _hwBound = prefs.getBytes(K_AUTH, &a, sizeof(a)) == sizeof(a) && a.hw == 1;
}

bool VaultManager::legacyFormat() {
    return prefs.getUChar(K_FORMAT, 0) == LEGACY_FORMAT_VERSION && prefs.isKey(K_LEGACY_VERIFIER);
}

bool VaultManager::isPinSet() {
    uint8_t fmt = prefs.getUChar(K_FORMAT, 0);
    if (fmt == VAULT_FORMAT_VERSION) return prefs.getBytesLength(K_AUTH) == sizeof(AuthBlob);
    return legacyFormat();
}

bool VaultManager::setPin(const char *pin) {
    size_t len = pin ? strlen(pin) : 0;
    if (len < PIN_NEW_MIN_LEN || len > PIN_MAX_LEN || isPinSet()) return false;

    wipe();
    secureRandom(_dek, sizeof(_dek));
    sodium_memzero(_keys, sizeof(_keys));
    _unlocked = true;
    bool ok = writeAuth(pin) && saveKeys() &&
              prefs.putUChar(K_FAILS, 0) == 1 &&
              prefs.putUChar(K_FORMAT, VAULT_FORMAT_VERSION) == 1;
    if (!ok) {
        wipe();
        return false;
    }
    _activeSlot = -1;
    _unlockedAt = millis();
    touch();
    return true;
}

void VaultManager::armThrottle(uint8_t fails) {
    uint32_t delayMs = 0;
    if (fails >= 3) {
        uint32_t shift = fails - 2;
        delayMs = (shift >= 6) ? 60000 : (1000u << shift);
    }
    _throttleStart = millis();
    _throttleDuration = delayMs;
}

uint32_t VaultManager::throttleRemainingMs() const {
    if (_throttleDuration == 0) return 0;
    uint32_t elapsed = millis() - _throttleStart;
    return (elapsed < _throttleDuration) ? (_throttleDuration - elapsed) : 0;
}

int VaultManager::remainingAttempts() {
    int fails = prefs.getUChar(K_FAILS, 0);
    return fails >= PIN_MAX_ATTEMPTS ? 0 : PIN_MAX_ATTEMPTS - fails;
}

bool VaultManager::beginAttempt(UnlockResult &early) {
    if (throttleRemainingMs() > 0) { early = UNLOCK_THROTTLED; return false; }
    uint8_t fails = prefs.getUChar(K_FAILS, 0);
    if (fails >= PIN_MAX_ATTEMPTS) {
        wipe();
        early = UNLOCK_WIPED;
        return false;
    }
    if (prefs.putUChar(K_FAILS, fails + 1) != 1 || prefs.getUChar(K_FAILS, 0) != fails + 1) {
        early = UNLOCK_ERROR;
        return false;
    }
    return true;
}

void VaultManager::endAttempt(bool ok, UnlockResult &result) {
    uint8_t fails = prefs.getUChar(K_FAILS, PIN_MAX_ATTEMPTS);
    if (ok) {
        prefs.putUChar(K_FAILS, 0);
        _throttleDuration = 0;
        result = UNLOCK_OK;
        return;
    }
    if (fails >= PIN_MAX_ATTEMPTS) {
        wipe();
        result = UNLOCK_WIPED;
        return;
    }
    armThrottle(fails);
    result = UNLOCK_WRONG_PIN;
}

UnlockResult VaultManager::unlock(const char *pin) {
    if (!isPinSet() || !pin) return UNLOCK_ERROR;
    if (prefs.getUChar(K_FORMAT, 0) == LEGACY_FORMAT_VERSION) return unlockLegacy(pin);
    return unlockV3(pin);
}

UnlockResult VaultManager::unlockV3(const char *pin) {
    UnlockResult result;
    if (!beginAttempt(result)) return result;

    AuthBlob a;
    if (prefs.getBytes(K_AUTH, &a, sizeof(a)) != sizeof(a) || !authBlobSane(a)) return UNLOCK_ERROR;
    _hwBound = a.hw == 1;

    uint8_t kek[32], dek[32];
    if (!deriveKek(pin, a.salt, a.iterations, kek)) return UNLOCK_ERROR;
    uint8_t aad[26];
    size_t aadLen;
    wrapAad(a, aad, &aadLen);
    bool ok = gcmOpen(kek, a.iv, aad, aadLen, a.wrappedDek, sizeof(dek), a.tag, dek);
    sodium_memzero(kek, sizeof(kek));

    endAttempt(ok, result);
    if (!ok) return result;

    memcpy(_dek, dek, sizeof(dek));
    sodium_memzero(dek, sizeof(dek));
    _unlocked = true;
    loadKeys();
    loadPasskeys();
    int saved = prefs.getUChar(K_ACTIVE, 0xFF);
    _activeSlot = keyAtSlot(saved) ? saved : slotForVisible(0);
    _unlockedAt = millis();
    touch();
    return UNLOCK_OK;
}

UnlockResult VaultManager::unlockLegacy(const char *pin) {
    UnlockResult result;
    if (!beginAttempt(result)) return result;

    uint8_t salt[16], stored[32];
    if (prefs.getBytes(K_LEGACY_SALT, salt, sizeof(salt)) != sizeof(salt) ||
        prefs.getBytes(K_LEGACY_VERIFIER, stored, sizeof(stored)) != sizeof(stored)) {
        return UNLOCK_ERROR;
    }

    uint8_t okm[64], calc[32];
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)pin, strlen(pin),
                                  salt, 16, LEGACY_PBKDF2_ITERATIONS, sizeof(okm), okm);
    static const char label[] = "ssh-vault/pin-verifier/v2";
    hmacSha256(okm + 32, 32, (const uint8_t *)label, sizeof(label) - 1, calc);
    bool ok = sodium_memcmp(stored, calc, sizeof(calc)) == 0;
    sodium_memzero(calc, sizeof(calc));
    sodium_memzero(stored, sizeof(stored));

    endAttempt(ok, result);
    if (!ok) {
        sodium_memzero(okm, sizeof(okm));
        return result;
    }

    uint8_t legacyKey[32];
    memcpy(legacyKey, okm, 32);
    sodium_memzero(okm, sizeof(okm));
    bool migrated = migrateFromLegacy(pin, legacyKey);
    sodium_memzero(legacyKey, sizeof(legacyKey));
    if (!migrated) {
        lock();
        return UNLOCK_ERROR;
    }

    _activeSlot = slotForVisible(0);
    if (_activeSlot >= 0) prefs.putUChar(K_ACTIVE, (uint8_t)_activeSlot);
    _unlockedAt = millis();
    touch();
    return UNLOCK_OK;
}

bool VaultManager::migrateFromLegacy(const char *pin, const uint8_t legacyKey[32]) {
    VaultKey legacy[MAX_KEYS];
    sodium_memzero(legacy, sizeof(legacy));
    if (prefs.getBytesLength(K_LEGACY_KEYS) == sizeof(legacy)) {
        prefs.getBytes(K_LEGACY_KEYS, legacy, sizeof(legacy));
    }

    secureRandom(_dek, sizeof(_dek));
    _unlocked = true;
    sodium_memzero(_keys, sizeof(_keys));
    bool ok = true;
    for (int i = 0; i < MAX_KEYS && ok; i++) {
        legacy[i].name[KEY_NAME_MAX_LEN] = 0;
        if (legacy[i].valid != 1) continue;
        uint8_t seed[32];
        if (!decryptSeed(i, legacy[i], legacyKey, LEGACY_FORMAT_VERSION, seed)) {
            ok = false;
            break;
        }
        _keys[i] = legacy[i];
        ok = encryptSeed(i, _keys[i], seed);
        sodium_memzero(seed, sizeof(seed));
    }
    sodium_memzero(legacy, sizeof(legacy));

    sodium_memzero(_passkeys, sizeof(_passkeys));
    memset(_passkeyUsed, 0, sizeof(_passkeyUsed));
    Preferences rk;
    if (ok && rk.begin(NS_LEGACY_RK, true)) {
        int dst = 0;
        for (int i = 0; i < LEGACY_RESIDENT_KEYS && dst < MAX_PASSKEYS; i++) {
            char k[8];
            snprintf(k, sizeof(k), "rk%d", i);
            LegacyPasskeyRecord rec;
            if (rk.getBytes(k, &rec, sizeof(rec)) != sizeof(rec) || rec.used != 1) continue;
            if (!keyAtSlot(rec.slot)) continue;
            Passkey &p = _passkeys[dst];
            p.slot = rec.slot;
            p.userIdLen = rec.userIdLen > USER_ID_MAX_LEN ? USER_ID_MAX_LEN : rec.userIdLen;
            memcpy(p.rpIdHash, rec.rpIdHash, 32);
            memcpy(p.nonce, rec.nonce, 32);
            memcpy(p.userId, rec.userId, p.userIdLen);
            p.rpId[0] = 0;
            memcpy(p.userName, rec.userName, USER_NAME_MAX_LEN);
            p.userName[USER_NAME_MAX_LEN] = 0;
            _passkeyUsed[dst++] = true;
        }
        rk.end();
    }

    for (int i = 0; i < MAX_PASSKEYS && ok; i++) {
        if (_passkeyUsed[i]) ok = savePasskey(i);
    }
    ok = ok && writeAuth(pin) && saveKeys() && prefs.putUChar(K_FORMAT, VAULT_FORMAT_VERSION) == 1;
    if (!ok) return false;
    compact();
    return true;
}

UnlockResult VaultManager::changePin(const char *oldPin, const char *newPin) {
    size_t len = newPin ? strlen(newPin) : 0;
    if (!_unlocked || !oldPin || len < PIN_NEW_MIN_LEN || len > PIN_MAX_LEN) return UNLOCK_ERROR;

    UnlockResult result;
    if (!beginAttempt(result)) {
        if (result == UNLOCK_WIPED) lock();
        return result;
    }

    AuthBlob a;
    if (prefs.getBytes(K_AUTH, &a, sizeof(a)) != sizeof(a) || !authBlobSane(a)) return UNLOCK_ERROR;
    uint8_t kek[32], dek[32];
    if (!deriveKek(oldPin, a.salt, a.iterations, kek)) return UNLOCK_ERROR;
    uint8_t aad[26];
    size_t aadLen;
    wrapAad(a, aad, &aadLen);
    bool ok = gcmOpen(kek, a.iv, aad, aadLen, a.wrappedDek, sizeof(dek), a.tag, dek);
    sodium_memzero(kek, sizeof(kek));
    if (ok) ok = sodium_memcmp(dek, _dek, sizeof(dek)) == 0;
    sodium_memzero(dek, sizeof(dek));

    endAttempt(ok, result);
    if (!ok) return result;

    if (!writeAuth(newPin)) return UNLOCK_ERROR;
    compact();
    touch();
    return UNLOCK_OK;
}

void VaultManager::lock() {
    _unlocked = false;
    _activeSlot = -1;
    sodium_memzero(_dek, sizeof(_dek));
    sodium_memzero(_keys, sizeof(_keys));
    sodium_memzero(_passkeys, sizeof(_passkeys));
    memset(_passkeyUsed, 0, sizeof(_passkeyUsed));
}

static void eraseSnapshot() {
    const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, nullptr);
    if (part && part->size >= SNAP_SIZE) esp_partition_erase_range(part, 0, SNAP_SIZE);
}

static void reformatNvs() {
    prefs.end();
    nvs_flash_erase();
    nvs_flash_init();
    prefs.begin(NVS_NS, false);
}

void VaultManager::wipe() {
    lock();
    reformatNvs();
    eraseSnapshot();
    _hwBound = false;
    _throttleDuration = 0;
    memset(_fidoEpoch, 0, sizeof(_fidoEpoch));
}

void VaultManager::factoryReset() {
    wipe();
}

bool VaultManager::saveKeys() {
    if (!_unlocked) return false;
    return prefs.putBytes(K_KEYS, _keys, sizeof(_keys)) == sizeof(_keys);
}

void VaultManager::loadKeys() {
    sodium_memzero(_keys, sizeof(_keys));
    if (prefs.getBytesLength(K_KEYS) == sizeof(_keys)) {
        prefs.getBytes(K_KEYS, _keys, sizeof(_keys));
    }
    for (int i = 0; i < MAX_KEYS; i++) {
        _keys[i].name[KEY_NAME_MAX_LEN] = 0;
        _keys[i].valid = (_keys[i].valid == 1) ? 1 : 0;
    }
}

void VaultManager::buildAad(int slot, const VaultKey &k, uint8_t version, uint8_t *aad, size_t *aadLen) const {
    size_t n = 0;
    memcpy(aad + n, "SSHV", 4);                   n += 4;
    aad[n++] = version;
    aad[n++] = (uint8_t)slot;
    memcpy(aad + n, k.name, sizeof(k.name));      n += sizeof(k.name);
    memcpy(aad + n, k.pubkey, sizeof(k.pubkey));  n += sizeof(k.pubkey);
    *aadLen = n;
}

bool VaultManager::decryptSeed(int slot, const VaultKey &k, const uint8_t key[32], uint8_t version,
                               uint8_t seed[32]) const {
    uint8_t aad[4 + 2 + sizeof(k.name) + sizeof(k.pubkey)];
    size_t aadLen;
    buildAad(slot, k, version, aad, &aadLen);
    if (!gcmOpen(key, k.iv, aad, aadLen, k.enc_seed, 32, k.tag, seed)) return false;

    uint8_t pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
    crypto_sign_ed25519_seed_keypair(pk, sk, seed);
    sodium_memzero(sk, sizeof(sk));
    if (sodium_memcmp(pk, k.pubkey, sizeof(pk)) != 0) {
        sodium_memzero(seed, 32);
        return false;
    }
    return true;
}

bool VaultManager::encryptSeed(int slot, VaultKey &k, const uint8_t seed[32]) {
    secureRandom(k.iv, sizeof(k.iv));
    uint8_t aad[4 + 2 + sizeof(k.name) + sizeof(k.pubkey)];
    size_t aadLen;
    buildAad(slot, k, VAULT_FORMAT_VERSION, aad, &aadLen);
    return gcmSeal(_dek, k.iv, aad, aadLen, seed, 32, k.enc_seed, k.tag);
}

int VaultManager::keyCount() const {
    if (!_unlocked) return 0;
    int c = 0;
    for (int i = 0; i < MAX_KEYS; i++) c += _keys[i].valid;
    return c;
}

int VaultManager::slotForVisible(int visibleIdx) const {
    if (!_unlocked || visibleIdx < 0) return -1;
    for (int i = 0; i < MAX_KEYS; i++) {
        if (_keys[i].valid && visibleIdx-- == 0) return i;
    }
    return -1;
}

const VaultKey *VaultManager::keyAtSlot(int slot) const {
    if (!_unlocked || slot < 0 || slot >= MAX_KEYS || !_keys[slot].valid) return nullptr;
    return &_keys[slot];
}

void VaultManager::setActiveSlot(int slot) {
    if (!keyAtSlot(slot)) return;
    _activeSlot = slot;
    prefs.putUChar(K_ACTIVE, (uint8_t)slot);
}

bool VaultManager::activePublic(char name[KEY_NAME_MAX_LEN + 1], uint8_t pub[32]) {
    if (_unlocked) {
        const VaultKey *k = keyAtSlot(_activeSlot);
        if (!k) return false;
        memcpy(name, k->name, KEY_NAME_MAX_LEN + 1);
        memcpy(pub, k->pubkey, 32);
        return true;
    }
    if (prefs.getUChar(K_FORMAT, 0) != VAULT_FORMAT_VERSION) return false;
    int slot = prefs.getUChar(K_ACTIVE, 0xFF);
    if (slot >= MAX_KEYS || prefs.getBytesLength(K_KEYS) != sizeof(_keys)) return false;
    VaultKey *all = (VaultKey *)malloc(sizeof(_keys));
    if (!all) return false;
    prefs.getBytes(K_KEYS, all, sizeof(_keys));
    bool ok = all[slot].valid == 1;
    if (ok) {
        memcpy(name, all[slot].name, KEY_NAME_MAX_LEN);
        name[KEY_NAME_MAX_LEN] = 0;
        memcpy(pub, all[slot].pubkey, 32);
    }
    free(all);
    return ok;
}

bool VaultManager::createKey(const char *name) {
    if (!_unlocked || !name || !*name || strlen(name) > KEY_NAME_MAX_LEN) return false;

    int slot = -1;
    for (int i = 0; i < MAX_KEYS; i++) {
        if (!_keys[i].valid) { slot = i; break; }
    }
    if (slot < 0) return false;

    uint8_t seed[crypto_sign_ed25519_SEEDBYTES];
    uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
    VaultKey k;
    memset(&k, 0, sizeof(k));

    secureRandom(seed, sizeof(seed));
    crypto_sign_ed25519_seed_keypair(k.pubkey, sk, seed);
    sodium_memzero(sk, sizeof(sk));
    strncpy(k.name, name, KEY_NAME_MAX_LEN);
    bool ok = encryptSeed(slot, k, seed);
    sodium_memzero(seed, sizeof(seed));
    if (!ok) return false;

    k.valid = 1;
    _keys[slot] = k;
    if (!saveKeys()) {
        sodium_memzero(&_keys[slot], sizeof(VaultKey));
        return false;
    }
    setActiveSlot(slot);
    return true;
}

bool VaultManager::deleteKey(int slot) {
    if (!keyAtSlot(slot)) return false;
    sodium_memzero(&_keys[slot], sizeof(VaultKey));
    for (int i = 0; i < MAX_PASSKEYS; i++) {
        if (_passkeyUsed[i] && _passkeys[i].slot == slot) {
            sodium_memzero(&_passkeys[i], sizeof(Passkey));
            _passkeyUsed[i] = false;
            char k[8];
            passkeyKeyName(i, k);
            prefs.remove(k);
        }
    }
    if (_activeSlot == slot) {
        _activeSlot = slotForVisible(0);
        if (_activeSlot >= 0) prefs.putUChar(K_ACTIVE, (uint8_t)_activeSlot);
        else prefs.remove(K_ACTIVE);
    }
    if (!saveKeys()) return false;
    compact();
    return true;
}

bool VaultManager::sign(int slot, const uint8_t *msg, size_t msgLen,
                        uint8_t sig[crypto_sign_ed25519_BYTES]) {
    const VaultKey *k = keyAtSlot(slot);
    if (!k) return false;

    uint8_t seed[crypto_sign_ed25519_SEEDBYTES];
    if (!decryptSeed(slot, *k, _dek, VAULT_FORMAT_VERSION, seed)) return false;

    uint8_t pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
    crypto_sign_ed25519_seed_keypair(pk, sk, seed);
    sodium_memzero(seed, sizeof(seed));
    crypto_sign_ed25519_detached(sig, nullptr, msg, msgLen, sk);
    sodium_memzero(sk, sizeof(sk));
    return true;
}

bool VaultManager::deriveSlotHmac(int slot, const char *domain,
                                  const uint8_t *data, size_t dataLen,
                                  uint8_t out[32]) {
    const VaultKey *k = keyAtSlot(slot);
    if (!k || !domain) return false;

    uint8_t seed[crypto_sign_ed25519_SEEDBYTES];
    if (!decryptSeed(slot, *k, _dek, VAULT_FORMAT_VERSION, seed)) return false;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, seed, sizeof(seed));
    mbedtls_md_hmac_update(&ctx, (const uint8_t *)domain, strlen(domain) + 1);
    mbedtls_md_hmac_update(&ctx, data, dataLen);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);

    sodium_memzero(seed, sizeof(seed));
    return true;
}

uint32_t VaultManager::nextSignCounter() {
    uint32_t cnt = prefs.getUInt(K_COUNTER, 0) + 1;
    prefs.putUInt(K_COUNTER, cnt);
    return cnt;
}

bool VaultManager::savePasskey(int idx) {
    char name[8];
    passkeyKeyName(idx, name);
    if (!_passkeyUsed[idx]) {
        prefs.remove(name);
        return true;
    }
    uint8_t blob[12 + sizeof(Passkey) + 16];
    uint8_t aad[6] = {'Z', 'V', 'P', 'K', VAULT_FORMAT_VERSION, (uint8_t)idx};
    secureRandom(blob, 12);
    bool ok = gcmSeal(_dek, blob, aad, sizeof(aad), (const uint8_t *)&_passkeys[idx], sizeof(Passkey),
                      blob + 12, blob + 12 + sizeof(Passkey));
    return ok && prefs.putBytes(name, blob, sizeof(blob)) == sizeof(blob);
}

void VaultManager::loadPasskeys() {
    sodium_memzero(_passkeys, sizeof(_passkeys));
    memset(_passkeyUsed, 0, sizeof(_passkeyUsed));
    for (int i = 0; i < MAX_PASSKEYS; i++) {
        char name[8];
        passkeyKeyName(i, name);
        uint8_t blob[12 + sizeof(Passkey) + 16];
        if (prefs.getBytesLength(name) != sizeof(blob)) continue;
        prefs.getBytes(name, blob, sizeof(blob));
        uint8_t aad[6] = {'Z', 'V', 'P', 'K', VAULT_FORMAT_VERSION, (uint8_t)i};
        if (gcmOpen(_dek, blob, aad, sizeof(aad), blob + 12, sizeof(Passkey),
                    blob + 12 + sizeof(Passkey), (uint8_t *)&_passkeys[i]) &&
            keyAtSlot(_passkeys[i].slot)) {
            _passkeys[i].rpId[RP_ID_MAX_LEN] = 0;
            _passkeys[i].userName[USER_NAME_MAX_LEN] = 0;
            if (_passkeys[i].userIdLen > USER_ID_MAX_LEN) _passkeys[i].userIdLen = USER_ID_MAX_LEN;
            _passkeyUsed[i] = true;
        } else {
            sodium_memzero(&_passkeys[i], sizeof(Passkey));
        }
    }
}

int VaultManager::passkeyCount(int slot) const {
    int c = 0;
    for (int i = 0; i < MAX_PASSKEYS; i++) c += (_passkeyUsed[i] && _passkeys[i].slot == slot);
    return c;
}

const Passkey *VaultManager::passkeyAt(int slot, int idx) const {
    for (int i = 0; i < MAX_PASSKEYS; i++) {
        if (_passkeyUsed[i] && _passkeys[i].slot == slot && idx-- == 0) return &_passkeys[i];
    }
    return nullptr;
}

int VaultManager::findPasskeys(int slot, const uint8_t rpIdHash[32], const Passkey **out, int max) const {
    int n = 0;
    for (int i = 0; i < MAX_PASSKEYS && n < max; i++) {
        if (_passkeyUsed[i] && _passkeys[i].slot == slot && memcmp(_passkeys[i].rpIdHash, rpIdHash, 32) == 0) {
            out[n++] = &_passkeys[i];
        }
    }
    return n;
}

const Passkey *VaultManager::findPasskeyByNonce(int slot, const uint8_t rpIdHash[32], const uint8_t nonce[32]) const {
    for (int i = 0; i < MAX_PASSKEYS; i++) {
        if (_passkeyUsed[i] && _passkeys[i].slot == slot &&
            memcmp(_passkeys[i].rpIdHash, rpIdHash, 32) == 0 &&
            memcmp(_passkeys[i].nonce, nonce, 32) == 0) {
            return &_passkeys[i];
        }
    }
    return nullptr;
}

static bool sameAccount(const Passkey &p, int slot, const uint8_t rpIdHash[32], const uint8_t *userId, uint8_t userIdLen) {
    return p.slot == slot && memcmp(p.rpIdHash, rpIdHash, 32) == 0 &&
           p.userIdLen == userIdLen && memcmp(p.userId, userId, userIdLen) == 0;
}

bool VaultManager::passkeyCapacityFor(int slot, const uint8_t rpIdHash[32], const uint8_t *userId, uint8_t userIdLen) const {
    for (int i = 0; i < MAX_PASSKEYS; i++) {
        if (!_passkeyUsed[i]) return true;
        if (sameAccount(_passkeys[i], slot, rpIdHash, userId, userIdLen)) return true;
    }
    return false;
}

StoreResult VaultManager::storePasskey(const Passkey &pk) {
    if (!_unlocked || !keyAtSlot(pk.slot)) return STORE_ERROR;
    int target = -1;
    for (int i = 0; i < MAX_PASSKEYS; i++) {
        if (_passkeyUsed[i] && sameAccount(_passkeys[i], pk.slot, pk.rpIdHash, pk.userId, pk.userIdLen)) {
            target = i;
            break;
        }
    }
    for (int i = 0; i < MAX_PASSKEYS && target < 0; i++) {
        if (!_passkeyUsed[i]) target = i;
    }
    if (target < 0) return STORE_FULL;
    _passkeys[target] = pk;
    _passkeyUsed[target] = true;
    return savePasskey(target) ? STORE_OK : STORE_ERROR;
}

bool VaultManager::deletePasskey(const Passkey *pk) {
    if (!_unlocked || pk < _passkeys || pk >= _passkeys + MAX_PASSKEYS) return false;
    int idx = pk - _passkeys;
    if (!_passkeyUsed[idx]) return false;
    sodium_memzero(&_passkeys[idx], sizeof(Passkey));
    _passkeyUsed[idx] = false;
    if (!savePasskey(idx)) return false;
    compact();
    return true;
}

bool VaultManager::resetFido() {
    if (!_unlocked) return false;
    uint8_t epoch[16];
    do { secureRandom(epoch, sizeof(epoch)); } while (sodium_is_zero(epoch, sizeof(epoch)));
    if (prefs.putBytes(K_EPOCH, epoch, sizeof(epoch)) != sizeof(epoch)) return false;
    memcpy(_fidoEpoch, epoch, sizeof(epoch));
    for (int i = 0; i < MAX_PASSKEYS; i++) {
        if (!_passkeyUsed[i]) continue;
        sodium_memzero(&_passkeys[i], sizeof(Passkey));
        _passkeyUsed[i] = false;
        savePasskey(i);
    }
    prefs.putUInt(K_COUNTER, 0);
    compact();
    return true;
}

bool VaultManager::fidoEpochIsLegacy() const {
    return sodium_is_zero(_fidoEpoch, sizeof(_fidoEpoch));
}

namespace {

struct SnapWriter {
    uint8_t *buf;
    size_t cap;
    size_t len = 0;
    bool ok = true;

    void blob(Preferences &store, const char *key) {
        size_t n = store.getBytesLength(key);
        size_t klen = strlen(key);
        if (n == 0) return;
        if (len + 1 + 1 + klen + 2 + n > cap) { ok = false; return; }
        buf[len++] = 'B';
        buf[len++] = (uint8_t)klen;
        memcpy(buf + len, key, klen); len += klen;
        buf[len++] = (uint8_t)(n >> 8);
        buf[len++] = (uint8_t)n;
        if (store.getBytes(key, buf + len, n) != n) { ok = false; return; }
        len += n;
    }

    void entry(char type, const char *key, const void *data, size_t n) {
        size_t klen = strlen(key);
        if (len + 1 + 1 + klen + 2 + n > cap) { ok = false; return; }
        buf[len++] = (uint8_t)type;
        buf[len++] = (uint8_t)klen;
        memcpy(buf + len, key, klen); len += klen;
        buf[len++] = (uint8_t)(n >> 8);
        buf[len++] = (uint8_t)n;
        memcpy(buf + len, data, n); len += n;
    }
};

bool applySnapshot(const uint8_t *buf, size_t len) {
    reformatNvs();
    size_t off = 0;
    bool ok = true;
    while (off < len && ok) {
        if (off + 2 > len) return false;
        char type = (char)buf[off++];
        size_t klen = buf[off++];
        if (klen == 0 || klen > 15 || off + klen + 2 > len) return false;
        char key[16];
        memcpy(key, buf + off, klen); key[klen] = 0; off += klen;
        size_t n = ((size_t)buf[off] << 8) | buf[off + 1]; off += 2;
        if (off + n > len) return false;
        const uint8_t *d = buf + off; off += n;
        if (type == 'U' && n == 1)      ok = prefs.putUChar(key, d[0]) == 1;
        else if (type == 'W' && n == 4) { uint32_t v; memcpy(&v, d, 4); ok = prefs.putUInt(key, v) == 4; }
        else if (type == 'B')           ok = prefs.putBytes(key, d, n) == n;
        else return false;
    }
    return ok;
}

}

bool VaultManager::compact() {
    const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, nullptr);
    if (!part || part->size < SNAP_SIZE) return false;

    uint8_t *buf = (uint8_t *)calloc(1, SNAP_SIZE);
    if (!buf) return false;
    SnapWriter w{buf + sizeof(SnapHeader), SNAP_SIZE - sizeof(SnapHeader)};

    uint8_t u8;
    uint32_t u32;
    u8 = prefs.getUChar(K_FORMAT, 0);         w.entry('U', K_FORMAT, &u8, 1);
    u8 = prefs.getUChar(K_FAILS, 0);          w.entry('U', K_FAILS, &u8, 1);
    if (prefs.isKey(K_ACTIVE)) { u8 = prefs.getUChar(K_ACTIVE, 0); w.entry('U', K_ACTIVE, &u8, 1); }
    u32 = prefs.getUInt(K_COUNTER, 0);        w.entry('W', K_COUNTER, &u32, 4);

    w.blob(prefs, K_AUTH);
    w.blob(prefs, K_KEYS);
    w.blob(prefs, K_EPOCH);
    for (int i = 0; i < MAX_PASSKEYS; i++) {
        char key[8];
        passkeyKeyName(i, key);
        w.blob(prefs, key);
    }

    bool ok = w.ok;
    if (ok) {
        SnapHeader h;
        h.magic = SNAP_MAGIC;
        h.len = w.len;
        mbedtls_sha256(w.buf, w.len, h.sha, 0);
        ok = esp_partition_erase_range(part, 0, SNAP_SIZE) == ESP_OK &&
             esp_partition_write(part, sizeof(SnapHeader), w.buf, w.len) == ESP_OK &&
             esp_partition_write(part, 0, &h, sizeof(h)) == ESP_OK;
    }
    if (ok) ok = applySnapshot(w.buf, w.len);
    if (ok) eraseSnapshot();
    sodium_memzero(buf, SNAP_SIZE);
    free(buf);
    return ok;
}

void VaultManager::restoreSnapshotIfPresent() {
    const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, nullptr);
    if (!part || part->size < SNAP_SIZE) return;
    SnapHeader h;
    if (esp_partition_read(part, 0, &h, sizeof(h)) != ESP_OK || h.magic != SNAP_MAGIC) return;
    if (h.len == 0 || h.len > SNAP_SIZE - sizeof(SnapHeader)) {
        eraseSnapshot();
        return;
    }
    uint8_t *buf = (uint8_t *)malloc(h.len);
    if (!buf) return;
    uint8_t sha[32];
    if (esp_partition_read(part, sizeof(SnapHeader), buf, h.len) == ESP_OK) {
        mbedtls_sha256(buf, h.len, sha, 0);
        if (memcmp(sha, h.sha, 32) != 0 || applySnapshot(buf, h.len)) eraseSnapshot();
    }
    sodium_memzero(buf, h.len);
    free(buf);
}
