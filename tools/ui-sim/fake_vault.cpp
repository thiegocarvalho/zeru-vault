#include "vault.h"
VaultManager Vault;
static bool g_pinSet = false;
void secureRandom(uint8_t *buf, size_t len) { memset(buf, 0, len); }
static void addKey(VaultKey *k, int slot, const char *name) {
    memset(&k[slot], 0, sizeof(VaultKey)); strncpy(k[slot].name, name, KEY_NAME_MAX_LEN);
    for (int i = 0; i < 32; i++) k[slot].pubkey[i] = (uint8_t)(slot * 37 + i * 11); k[slot].valid = 1;
}
static void addPasskey(Passkey *p, bool *used, int idx, int slot, const char *rp, const char *user) {
    memset(&p[idx], 0, sizeof(Passkey)); p[idx].slot = slot; strncpy(p[idx].rpId, rp, RP_ID_MAX_LEN);
    strncpy(p[idx].userName, user, USER_NAME_MAX_LEN); p[idx].userIdLen = 4; used[idx] = true;
}
bool VaultManager::isPinSet() { return g_pinSet; }
bool VaultManager::setPin(const char *) { g_pinSet = true; _hwBound = true; _unlocked = true; _unlockedAt = millis(); return true; }
UnlockResult VaultManager::unlock(const char *) {
    _unlocked = true; _hwBound = true; _unlockedAt = millis() - 23 * 60000UL;
    addKey(_keys, 0, "GITHUB"); addKey(_keys, 1, "PROD_SERVERS"); addKey(_keys, 2, "HOMELAB");
    memset(_passkeyUsed, 0, sizeof(_passkeyUsed));
    addPasskey(_passkeys, _passkeyUsed, 0, 1, "github.com", "alice");
    addPasskey(_passkeys, _passkeyUsed, 1, 1, "accounts.google.com", "alice@gmail.com");
    addPasskey(_passkeys, _passkeyUsed, 2, 1, "login.microsoftonline.com", "alice@contoso.com");
    addPasskey(_passkeys, _passkeyUsed, 3, 1, "ssh:", "");
    _activeSlot = 1; return UNLOCK_OK;
}
UnlockResult VaultManager::changePin(const char *, const char *) { return UNLOCK_OK; }
void VaultManager::lock() { _unlocked = false; }
void VaultManager::factoryReset() { _unlocked = false; g_pinSet = false; }
int VaultManager::remainingAttempts() { return PIN_MAX_ATTEMPTS; }
uint32_t VaultManager::throttleRemainingMs() const { return 0; }
int VaultManager::keyCount() const { if (!_unlocked) return 0; int c = 0; for (int i = 0; i < MAX_KEYS; i++) c += _keys[i].valid; return c; }
int VaultManager::slotForVisible(int v) const { if (!_unlocked) return -1; for (int i = 0; i < MAX_KEYS; i++) if (_keys[i].valid && v-- == 0) return i; return -1; }
const VaultKey *VaultManager::keyAtSlot(int s) const { if (!_unlocked || s < 0 || s >= MAX_KEYS || !_keys[s].valid) return nullptr; return &_keys[s]; }
void VaultManager::setActiveSlot(int s) { if (keyAtSlot(s)) _activeSlot = s; }
bool VaultManager::createKey(const char *n) { addKey(_keys, 3, n); return true; }
bool VaultManager::deleteKey(int) { return true; }
int VaultManager::passkeyCount(int slot) const { int c = 0; for (int i = 0; i < MAX_PASSKEYS; i++) c += _passkeyUsed[i] && _passkeys[i].slot == slot; return c; }
const Passkey *VaultManager::passkeyAt(int slot, int idx) const { for (int i = 0; i < MAX_PASSKEYS; i++) if (_passkeyUsed[i] && _passkeys[i].slot == slot && idx-- == 0) return &_passkeys[i]; return nullptr; }
bool VaultManager::deletePasskey(const Passkey *) { return true; }
bool VaultManager::resetFido() { return true; }
