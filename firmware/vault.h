#pragma once
#include <Arduino.h>
#include <sodium.h>

#define FIRMWARE_VERSION      "2.0.0"

#define MAX_KEYS              8
#define MAX_PASSKEYS          24
#define PIN_MIN_LEN           4
#define PIN_NEW_MIN_LEN       6
#define PIN_MAX_LEN           8
#define KEY_NAME_MAX_LEN      20
#define PIN_MAX_ATTEMPTS      10
#define VAULT_FORMAT_VERSION  3
#define RP_ID_MAX_LEN         63
#define USER_NAME_MAX_LEN     32
#define USER_ID_MAX_LEN       64
#define AUTO_LOCK_IDLE_MS     (15UL * 60UL * 1000UL)
#define SESSION_MAX_MS        (12UL * 60UL * 60UL * 1000UL)

struct VaultKey {
    char    name[KEY_NAME_MAX_LEN + 1];
    uint8_t pubkey[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t enc_seed[crypto_sign_ed25519_SEEDBYTES];
    uint8_t iv[12];
    uint8_t tag[16];
    uint8_t valid;
};

struct Passkey {
    uint8_t slot;
    uint8_t userIdLen;
    uint8_t rpIdHash[32];
    uint8_t nonce[32];
    uint8_t userId[USER_ID_MAX_LEN];
    char    rpId[RP_ID_MAX_LEN + 1];
    char    userName[USER_NAME_MAX_LEN + 1];
};

enum UnlockResult {
    UNLOCK_OK = 0,
    UNLOCK_WRONG_PIN,
    UNLOCK_THROTTLED,
    UNLOCK_WIPED,
    UNLOCK_ERROR
};

enum StoreResult {
    STORE_OK = 0,
    STORE_FULL,
    STORE_ERROR
};

class VaultManager {
public:
    bool begin();

    bool isPinSet();
    bool hardwareBound() const { return _hwBound; }
    bool setPin(const char *pin);
    UnlockResult unlock(const char *pin);
    UnlockResult changePin(const char *oldPin, const char *newPin);
    void lock();
    void factoryReset();
    bool isUnlocked() const { return _unlocked; }

    int  remainingAttempts();
    uint32_t throttleRemainingMs() const;

    int  keyCount() const;
    int  slotForVisible(int visibleIdx) const;
    const VaultKey *keyAtSlot(int slot) const;

    int  activeSlot() const { return _activeSlot; }
    void setActiveSlot(int slot);
    bool activePublic(char name[KEY_NAME_MAX_LEN + 1], uint8_t pub[32]);

    bool createKey(const char *name);
    bool deleteKey(int slot);
    bool sign(int slot, const uint8_t *msg, size_t msgLen, uint8_t sig[crypto_sign_ed25519_BYTES]);
    bool deriveSlotHmac(int slot, const char *domain, const uint8_t *data, size_t dataLen, uint8_t out[32]);
    uint32_t nextSignCounter();

    int  passkeyCount(int slot) const;
    const Passkey *passkeyAt(int slot, int idx) const;
    int  findPasskeys(int slot, const uint8_t rpIdHash[32], const Passkey **out, int max) const;
    const Passkey *findPasskeyByNonce(int slot, const uint8_t rpIdHash[32], const uint8_t nonce[32]) const;
    bool passkeyCapacityFor(int slot, const uint8_t rpIdHash[32], const uint8_t *userId, uint8_t userIdLen) const;
    StoreResult storePasskey(const Passkey &pk);
    bool deletePasskey(const Passkey *pk);
    bool resetFido();
    const uint8_t *fidoEpoch() const { return _fidoEpoch; }
    bool fidoEpochIsLegacy() const;

    void touch() { _lastActivity = millis(); }
    uint32_t idleMs() const { return millis() - _lastActivity; }
    uint32_t sessionMs() const { return _unlocked ? millis() - _unlockedAt : 0; }

private:
    bool     _unlocked = false;
    bool     _hwBound = false;
    uint8_t  _dek[32];
    VaultKey _keys[MAX_KEYS];
    Passkey  _passkeys[MAX_PASSKEYS];
    bool     _passkeyUsed[MAX_PASSKEYS];
    uint8_t  _fidoEpoch[16];
    int      _activeSlot = -1;
    uint32_t _throttleStart = 0;
    uint32_t _throttleDuration = 0;
    uint32_t _lastActivity = 0;
    uint32_t _unlockedAt = 0;

    bool legacyFormat();
    bool deriveKek(const char *pin, const uint8_t salt[16], uint32_t iterations, uint8_t kek[32]);
    uint32_t calibrateIterations();
    bool writeAuth(const char *pin);
    UnlockResult unlockV3(const char *pin);
    UnlockResult unlockLegacy(const char *pin);
    bool migrateFromLegacy(const char *pin, const uint8_t legacyKey[32]);
    bool beginAttempt(UnlockResult &early);
    void endAttempt(bool ok, UnlockResult &result);

    void buildAad(int slot, const VaultKey &k, uint8_t version, uint8_t *aad, size_t *aadLen) const;
    bool decryptSeed(int slot, const VaultKey &k, const uint8_t key[32], uint8_t version, uint8_t seed[32]) const;
    bool encryptSeed(int slot, VaultKey &k, const uint8_t seed[32]);
    bool savePasskey(int idx);
    void loadPasskeys();
    void armThrottle(uint8_t fails);
    void wipe();
    bool saveKeys();
    void loadKeys();
    void loadMeta();
    bool compact();
    void restoreSnapshotIfPresent();
};

void secureRandom(uint8_t *buf, size_t len);

extern VaultManager Vault;
