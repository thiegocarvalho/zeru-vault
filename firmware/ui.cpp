#include "ui.h"
#include "pin_config.h"
#include <Arduino_GFX_Library.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <math.h>

#include "fonts/FreeSans9pt7b.h"
#include "fonts/FreeSansBold9pt7b.h"
#include "fonts/FreeSansBold12pt7b.h"
#include "fonts/FreeSansBold18pt7b.h"
#include "fonts/FreeMonoBold12pt7b.h"

UserInterface UI;

static Arduino_DataBus *bus = new Arduino_ESP32LCD8(
    PIN_LCD_DC, PIN_LCD_CS, PIN_LCD_WR, PIN_LCD_RD,
    PIN_LCD_D0, PIN_LCD_D1, PIN_LCD_D2, PIN_LCD_D3,
    PIN_LCD_D4, PIN_LCD_D5, PIN_LCD_D6, PIN_LCD_D7);

static Arduino_GFX *panel = new Arduino_ST7789(
    bus, PIN_LCD_RES, 1, true,
    LCD_WIDTH, LCD_HEIGHT, LCD_COL_OFFSET, LCD_ROW_OFFSET,
    LCD_COL_OFFSET, LCD_ROW_OFFSET);

static constexpr int W = 320;
static constexpr int H = 170;
static constexpr int RAIL_W = 20;
static constexpr int CONTENT_W = W - RAIL_W;

static Arduino_Canvas *g = new Arduino_Canvas(W, H, panel);

static constexpr uint16_t rgb(uint8_t r, uint8_t gg, uint8_t b) {
    return (uint16_t)(((r & 0xF8) << 8) | ((gg & 0xFC) << 3) | (b >> 3));
}

static constexpr uint16_t C_BG    = rgb(7, 9, 16);
static constexpr uint16_t C_SURF  = rgb(16, 20, 32);
static constexpr uint16_t C_SURF2 = rgb(28, 34, 54);
static constexpr uint16_t C_LINE  = rgb(42, 50, 74);
static constexpr uint16_t C_TEXT  = rgb(238, 242, 250);
static constexpr uint16_t C_MUTED = rgb(128, 138, 164);
static constexpr uint16_t C_CYAN  = rgb(0, 212, 255);
static constexpr uint16_t C_GREEN = rgb(40, 228, 140);
static constexpr uint16_t C_AMBER = rgb(255, 182, 0);
static constexpr uint16_t C_RED   = rgb(255, 70, 96);

static const GFXfont *F_REG  = &FreeSans9pt7b;
static const GFXfont *F_B9   = &FreeSansBold9pt7b;
static const GFXfont *F_B12  = &FreeSansBold12pt7b;
static const GFXfont *F_B18  = &FreeSansBold18pt7b;
static const GFXfont *F_MONO = &FreeMonoBold12pt7b;

static constexpr uint32_t FRAME_MS = 33;
static constexpr uint32_t FADE_MS  = 160;
static constexpr uint32_t BOOT_MS  = 1700;
static constexpr uint32_t SIGN_MS  = 30000;
static constexpr uint32_t SIGN_ARM_MS  = 700;
static constexpr uint32_t GEN_MS   = 900;

static const char *PIN_ITEMS[] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "DEL", "OK"};
static constexpr int PIN_N = 12;

static const char CHARSET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
static constexpr int CHARSET_LEN = sizeof(CHARSET) - 1;
static char g_charStore[CHARSET_LEN][2];
static const char *CHAR_ITEMS[CHARSET_LEN + 2];
static constexpr int CHAR_N = CHARSET_LEN + 2;

static bool g_settling = false;

static uint16_t blend(uint16_t a, uint16_t b, uint8_t t) {
    uint32_t ra = a >> 11, ga = (a >> 5) & 0x3F, ba = a & 0x1F;
    uint32_t rb = b >> 11, gb = (b >> 5) & 0x3F, bb = b & 0x1F;
    uint32_t r = (ra * t + rb * (255 - t)) / 255;
    uint32_t gg = (ga * t + gb * (255 - t)) / 255;
    uint32_t bl = (ba * t + bb * (255 - t)) / 255;
    return (uint16_t)((r << 11) | (gg << 5) | bl);
}

static float clamp01(float x) { return x < 0 ? 0 : (x > 1 ? 1 : x); }
static float easeOut(float t) { t = clamp01(t); float u = 1 - t; return 1 - u * u * u; }
static float easeBack(float t) {
    t = clamp01(t);
    const float c1 = 1.70158f, c3 = c1 + 1;
    float u = t - 1;
    return 1 + c3 * u * u * u + c1 * u * u;
}
static float pulse(uint32_t now, float hz) { return 0.5f + 0.5f * sinf(now * 0.001f * hz * 2 * PI); }

static bool approach(float &v, float target) {
    float d = target - v;
    if (fabsf(d) < 0.01f) { v = target; return false; }
    v += d * 0.35f;
    return true;
}

static float wrapDelta(float d, int n) {
    while (d > n / 2.0f) d -= n;
    while (d < -n / 2.0f) d += n;
    return d;
}

static bool approachWrap(float &pos, int target, int n) {
    float d = wrapDelta(target - pos, n);
    if (fabsf(d) < 0.01f) { pos = target; return false; }
    pos += d * 0.35f;
    if (pos < 0) pos += n;
    if (pos >= n) pos -= n;
    return true;
}

static void font(const GFXfont *f) { g->setFont(f); g->setTextSize(1); }
static void smallFont() { g->setFont((const GFXfont *)NULL); g->setTextSize(1); }

static void text(int x, int y, const char *s, uint16_t c) {
    g->setTextColor(c);
    g->setCursor(x, y);
    g->print(s);
}

static int textWidth(const char *s) {
    int16_t x1, y1; uint16_t w, h;
    g->getTextBounds(s, 0, 0, &x1, &y1, &w, &h);
    return w;
}

static void textCenter(int cx, int y, const char *s, uint16_t c) {
    int16_t x1, y1; uint16_t w, h;
    g->getTextBounds(s, 0, y, &x1, &y1, &w, &h);
    text(cx - (int)w / 2 - x1, y, s, c);
}

static void textRight(int rx, int y, const char *s, uint16_t c) {
    int16_t x1, y1; uint16_t w, h;
    g->getTextBounds(s, 0, y, &x1, &y1, &w, &h);
    text(rx - (int)w - x1, y, s, c);
}

static void fitLeftEllipsis(const char *src, char *dst, size_t dstMax, int maxW) {
    size_t len = strlen(src);
    size_t start = 0;
    snprintf(dst, dstMax, "%s", src);
    while (textWidth(dst) > maxW && start < len) {
        start++;
        snprintf(dst, dstMax, "..%s", src + start);
    }
}

static void thickLine(int x0, int y0, int x1, int y1, uint16_t c) {
    for (int dx = -1; dx <= 1; dx++)
        for (int dy = -1; dy <= 1; dy++)
            g->drawLine(x0 + dx, y0 + dy, x1 + dx, y1 + dy, c);
}

static void lockIcon(int cx, int cy, uint16_t c, uint16_t bg, float open) {
    int lift = (int)(open * 8);
    g->fillArc(cx, cy - 6 - lift, 13, 8, 180, 360, c);
    g->fillRect(cx - 13, cy - 6 - lift, 5, 8 + lift, c);
    if (open < 0.05f) g->fillRect(cx + 8, cy - 6, 5, 8, c);
    g->fillRoundRect(cx - 17, cy, 34, 26, 5, c);
    g->fillCircle(cx, cy + 10, 4, bg);
    g->fillRect(cx - 1, cy + 12, 3, 7, bg);
}

static void statusIcon(int cx, int cy, MsgKind kind, float t) {
    float s = easeBack(t);
    int r = (int)(28 * s);
    if (r < 1) return;
    uint16_t c = kind == MSG_OK ? C_GREEN : (kind == MSG_ERROR ? C_RED : C_AMBER);
    g->fillCircle(cx, cy, r + 6, blend(c, C_BG, 50));
    g->fillCircle(cx, cy, r, c);
    float k = clamp01((t - 0.45f) / 0.55f);
    if (k <= 0) return;
    if (kind == MSG_OK) {
        float a = clamp01(k * 2), b = clamp01(k * 2 - 1);
        int x0 = cx - 12, y0 = cy + 1, x1 = cx - 4, y1 = cy + 9, x2 = cx + 13, y2 = cy - 9;
        thickLine(x0, y0, x0 + (int)((x1 - x0) * a), y0 + (int)((y1 - y0) * a), C_BG);
        if (b > 0) thickLine(x1, y1, x1 + (int)((x2 - x1) * b), y1 + (int)((y2 - y1) * b), C_BG);
    } else if (kind == MSG_ERROR) {
        int d = (int)(10 * k);
        thickLine(cx - d, cy - d, cx + d, cy + d, C_BG);
        thickLine(cx - d, cy + d, cx + d, cy - d, C_BG);
    } else {
        g->fillRoundRect(cx - 2, cy - 13, 5, (int)(17 * k), 2, C_BG);
        if (k > 0.8f) g->fillCircle(cx, cy + 10, 3, C_BG);
    }
}

static void spinner(int cx, int cy, uint32_t now, uint16_t c) {
    float a = fmodf(now * 0.4f, 360.0f);
    g->fillArc(cx, cy, 26, 21, 0, 360, C_SURF2);
    g->fillArc(cx, cy, 26, 21, a, a + 100, c);
    g->fillArc(cx, cy, 26, 21, a + 180, a + 210, blend(c, C_SURF2, 120));
}

static void fadeFramebuffer(uint8_t k) {
    uint16_t *fb = g->getFramebuffer();
    if (!fb || k >= 32) return;
    for (int i = 0; i < W * H; i++) {
        uint32_t c = fb[i];
        c = ((c | (c << 16)) & 0x07E0F81Fu) * k >> 5;
        c &= 0x07E0F81Fu;
        fb[i] = (uint16_t)(c | (c >> 16));
    }
}

void UserInterface::begin(ButtonManager *buttons) {
    _btn = buttons;

    for (int i = 0; i < CHARSET_LEN; i++) {
        g_charStore[i][0] = CHARSET[i];
        g_charStore[i][1] = 0;
        CHAR_ITEMS[i] = g_charStore[i];
    }
    CHAR_ITEMS[CHARSET_LEN] = "DEL";
    CHAR_ITEMS[CHARSET_LEN + 1] = "OK";

    pinMode(PIN_POWER_ON, OUTPUT);
    digitalWrite(PIN_POWER_ON, HIGH);
    delay(10);

    g->begin();
    g->fillScreen(C_BG);
    g->flush();

    pinMode(PIN_LCD_BL, OUTPUT);
    digitalWrite(PIN_LCD_BL, HIGH);

    clearPinBuffers();
    _unlockReason[0] = 0;
    go(ST_BOOT);
}

void UserInterface::go(UiState s) {
    _prevState = _state;
    _state = s;
    _stateSince = millis();
    _dirty = true;
    if (_btn) _btn->setRepeat(s != ST_SIGN && s != ST_CONFIRM);
}

void UserInterface::showMessage(MsgKind kind, const char *title, const char *sub, UiState next, uint32_t ms) {
    _msgKind = kind;
    strncpy(_msgTitle, title, sizeof(_msgTitle) - 1);
    _msgTitle[sizeof(_msgTitle) - 1] = 0;
    strncpy(_msgSub, sub ? sub : "", sizeof(_msgSub) - 1);
    _msgSub[sizeof(_msgSub) - 1] = 0;
    _msgNext = next;
    _msgDuration = ms;
    go(ST_MESSAGE);
}

bool UserInterface::isUnlockedState(UiState s) const {
    switch (s) {
        case ST_KEYS: case ST_KEY_ACTIONS: case ST_FINGERPRINT: case ST_NAME: case ST_GENERATING:
        case ST_SIGN: case ST_SETTINGS: case ST_PASSKEYS: case ST_ABOUT: case ST_BACKUP_NOTICE:
            return true;
        case ST_CONFIRM:
            return _confirmAction != CONFIRM_FACTORY_RESET;
        default:
            return false;
    }
}

bool UserInterface::animating() const {
    uint32_t now = millis();
    if (now - _stateSince < FADE_MS + FRAME_MS) return true;
    if (g_settling) return true;
    if (_btn && _btn->holdProgress() > 0) return true;
    if (now - _pinPopAt < 250) return true;
    switch (_state) {
        case ST_BOOT: case ST_LOCKED: case ST_WORKING: case ST_MESSAGE:
        case ST_GENERATING: case ST_SIGN: case ST_NAME:
            return true;
        default:
            return false;
    }
}

void UserInterface::clearPinBuffers() {
    sodium_memzero(_pin, sizeof(_pin));
    sodium_memzero(_pinFirst, sizeof(_pinFirst));
    sodium_memzero(_pinOld, sizeof(_pinOld));
    _pinLen = 0;
}

void UserInterface::resetListSelection(int sel) {
    _sel = sel;
    _selAnim = (float)sel;
    _scrollAnim = 0;
}

void UserInterface::computeFingerprints() {
    for (int s = 0; s < MAX_KEYS; s++) {
        _fingerprints[s][0] = 0;
        const VaultKey *k = Vault.keyAtSlot(s);
        if (!k) continue;
        uint8_t blob[4 + 11 + 4 + 32];
        memcpy(blob, "\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20", 19);
        memcpy(blob + 19, k->pubkey, 32);
        uint8_t digest[32];
        mbedtls_sha256(blob, sizeof(blob), digest, 0);
        unsigned char b64[48];
        size_t olen = 0;
        mbedtls_base64_encode(b64, sizeof(b64), &olen, digest, sizeof(digest));
        while (olen > 0 && b64[olen - 1] == '=') olen--;
        b64[olen] = 0;
        snprintf(_fingerprints[s], sizeof(_fingerprints[s]), "SHA256:%.43s", (const char *)b64);
    }
}

static int visibleOfSlot(int slot) {
    int count = Vault.keyCount();
    for (int i = 0; i < count; i++) {
        if (Vault.slotForVisible(i) == slot) return i;
    }
    return 0;
}

void UserInterface::requestSignConfirmation(const SignPrompt &prompt) {
    _prompt = prompt;
    _prompt.keyName[KEY_NAME_MAX_LEN] = 0;
    _prompt.target[RP_ID_MAX_LEN] = 0;
    _prompt.detail[sizeof(_prompt.detail) - 1] = 0;
    if (_prompt.accountCount < 0) _prompt.accountCount = 0;
    if (_prompt.accountCount > PROMPT_MAX_ACCOUNTS) _prompt.accountCount = PROMPT_MAX_ACCOUNTS;
    _signAccount = 0;

    switch (_state) {
        case ST_KEYS: case ST_KEY_ACTIONS: case ST_FINGERPRINT: case ST_SETTINGS:
        case ST_PASSKEYS: case ST_ABOUT:
            _signReturn = _state;
            break;
        default:
            _signReturn = ST_KEYS;
            break;
    }
    if (_state == ST_WORKING) runWork();
    else if (_state == ST_GENERATING) finishGenerating();
    if (_state == ST_PIN || _state == ST_NAME || _state == ST_CONFIRM) clearPinBuffers();

    _signDecision = SIGN_NONE;
    uint32_t now = millis();
    _signDeadline = now + SIGN_MS;
    _signArmedAt = now + SIGN_ARM_MS;
    _signChoice = signOptionCount() - 1;
    if (_btn) _btn->suppressUntilRelease();
    go(ST_SIGN);
}

void UserInterface::cancelSignConfirmation() {
    if (_state == ST_SIGN) go(Vault.isUnlocked() ? _signReturn : ST_LOCKED);
}

void UserInterface::requestUnlock(const char *reason) {
    strncpy(_unlockReason, reason ? reason : "", sizeof(_unlockReason) - 1);
    _unlockReason[sizeof(_unlockReason) - 1] = 0;
    if (_state == ST_LOCKED && Vault.isPinSet() && Vault.throttleRemainingMs() == 0) {
        startPin(PIN_UNLOCK);
    }
    _dirty = true;
}

void UserInterface::clearUnlockRequest() {
    _unlockReason[0] = 0;
    _unlockDeclined = false;
    _dirty = true;
}

bool UserInterface::takeUnlockDeclined() {
    bool declined = _unlockDeclined;
    _unlockDeclined = false;
    return declined;
}

void UserInterface::notifyAutoLocked(const char *reason) {
    clearPinBuffers();
    showMessage(MSG_WARN, "Vault locked", reason, ST_LOCKED, 1800);
}

void UserInterface::notify(MsgKind kind, const char *title, const char *sub) {
    switch (_state) {
        case ST_KEYS: case ST_KEY_ACTIONS: case ST_FINGERPRINT: case ST_SETTINGS:
        case ST_PASSKEYS: case ST_ABOUT: case ST_LOCKED:
            showMessage(kind, title, sub, _state, 2600);
            break;
        default:
            break;
    }
}

int UserInterface::pinMinLen() const {
    return (_pinMode == PIN_UNLOCK || _pinMode == PIN_CHANGE_OLD) ? PIN_MIN_LEN : PIN_NEW_MIN_LEN;
}

void UserInterface::randomizePinCursor() {
    uint8_t r;
    do { secureRandom(&r, 1); } while (r >= 250);
    _pinCursor = r % 10;
}

void UserInterface::startPin(PinMode mode) {
    clearPinBuffers();
    _pinMode = mode;
    randomizePinCursor();
    _pinWheel = (float)_pinCursor;
    go(ST_PIN);
}

void UserInterface::startWork(WorkAction action) {
    _work = action;
    go(ST_WORKING);
}

void UserInterface::openConfirm(ConfirmAction action, UiState back) {
    _confirmAction = action;
    _confirmChoice = 0;
    _confirmReturn = back;
    go(ST_CONFIRM);
}

void UserInterface::onLocked(ButtonEvent e) {
    if (e == BTN_BOTH_HOLD && Vault.isPinSet()) {
        openConfirm(CONFIRM_FACTORY_RESET, ST_LOCKED);
        return;
    }
    if (e != BTN_BOTH_CLICK) { _dirty = true; return; }
    if (Vault.throttleRemainingMs() > 0) { _dirty = true; return; }
    startPin(Vault.isPinSet() ? PIN_UNLOCK : PIN_NEW);
}

void UserInterface::onPin(ButtonEvent e) {
    switch (e) {
        case BTN_LEFT_CLICK:  _pinCursor = (_pinCursor + PIN_N - 1) % PIN_N; break;
        case BTN_RIGHT_CLICK: _pinCursor = (_pinCursor + 1) % PIN_N; break;
        case BTN_BOTH_HOLD:
            if (_pinMode == PIN_CONFIRM) {
                startPin(PIN_NEW);
            } else if (_pinMode == PIN_CHANGE_CONFIRM) {
                sodium_memzero(_pin, sizeof(_pin));
                sodium_memzero(_pinFirst, sizeof(_pinFirst));
                _pinLen = 0;
                randomizePinCursor();
                _pinMode = PIN_CHANGE_NEW;
                go(ST_PIN);
            } else if (_pinMode == PIN_CHANGE_OLD || _pinMode == PIN_CHANGE_NEW) {
                clearPinBuffers();
                resetListSelection(0);
                go(ST_SETTINGS);
            } else {
                clearPinBuffers();
                if (_unlockReason[0]) {
                    _unlockReason[0] = 0;
                    _unlockDeclined = true;
                }
                go(ST_LOCKED);
            }
            return;
        case BTN_BOTH_CLICK:
            if (_pinCursor < 10) {
                if (_pinLen < PIN_MAX_LEN) {
                    _pin[_pinLen++] = '0' + _pinCursor;
                    _pin[_pinLen] = 0;
                    _pinPopAt = millis();
                    if (_pinLen == PIN_MAX_LEN) _pinCursor = 11;
                    else randomizePinCursor();
                }
            } else if (_pinCursor == 10) {
                if (_pinLen > 0) _pin[--_pinLen] = 0;
            } else if (_pinLen >= pinMinLen()) {
                submitPin();
                return;
            }
            break;
        default: break;
    }
    _dirty = true;
}

void UserInterface::submitPin() {
    bool same = strlen(_pin) == strlen(_pinFirst) &&
                sodium_memcmp(_pin, _pinFirst, strlen(_pin)) == 0;
    switch (_pinMode) {
        case PIN_UNLOCK:
            startWork(WORK_UNLOCK);
            return;
        case PIN_NEW:
        case PIN_CHANGE_NEW:
            memcpy(_pinFirst, _pin, sizeof(_pin));
            sodium_memzero(_pin, sizeof(_pin));
            _pinMode = _pinMode == PIN_NEW ? PIN_CONFIRM : PIN_CHANGE_CONFIRM;
            break;
        case PIN_CHANGE_OLD:
            memcpy(_pinOld, _pin, sizeof(_pin));
            sodium_memzero(_pin, sizeof(_pin));
            _pinMode = PIN_CHANGE_NEW;
            break;
        case PIN_CONFIRM:
        case PIN_CHANGE_CONFIRM:
            if (same) {
                startWork(_pinMode == PIN_CONFIRM ? WORK_SET_PIN : WORK_CHANGE_PIN);
                return;
            }
            sodium_memzero(_pin, sizeof(_pin));
            sodium_memzero(_pinFirst, sizeof(_pinFirst));
            _pinMode = _pinMode == PIN_CONFIRM ? PIN_NEW : PIN_CHANGE_NEW;
            _pinLen = 0;
            randomizePinCursor();
            showMessage(MSG_ERROR, "PIN mismatch", "Please try again", ST_PIN);
            return;
    }
    _pinLen = 0;
    randomizePinCursor();
    go(ST_PIN);
}

void UserInterface::runWork() {
    char sub[64];
    switch (_work) {
        case WORK_UNLOCK: {
            bool shortPin = strlen(_pin) < PIN_NEW_MIN_LEN;
            UnlockResult r = Vault.unlock(_pin);
            clearPinBuffers();
            randomizePinCursor();
            switch (r) {
                case UNLOCK_OK: {
                    computeFingerprints();
                    resetListSelection(visibleOfSlot(Vault.activeSlot()));
                    const VaultKey *k = Vault.keyAtSlot(Vault.activeSlot());
                    if (shortPin) {
                        showMessage(MSG_WARN, "Unlocked: weak PIN", "Change it to 6-8 digits in Settings", ST_KEYS, 2600);
                        break;
                    }
                    snprintf(sub, sizeof(sub), k ? "Active key: %s" : "Create your first key", k ? k->name : "");
                    showMessage(MSG_OK, "Unlocked", sub, ST_KEYS, 900);
                    break;
                }
                case UNLOCK_WRONG_PIN:
                    snprintf(sub, sizeof(sub), "%d attempts remaining", Vault.remainingAttempts());
                    showMessage(MSG_ERROR, "Wrong PIN", sub, ST_PIN, 1500);
                    break;
                case UNLOCK_THROTTLED:
                    showMessage(MSG_WARN, "Please wait", "Too many attempts", ST_LOCKED);
                    break;
                case UNLOCK_WIPED:
                    computeFingerprints();
                    showMessage(MSG_ERROR, "Vault wiped", "Attempt limit reached", ST_LOCKED, 3500);
                    break;
                default:
                    showMessage(MSG_ERROR, "Error", "Failed to read vault", ST_LOCKED);
                    break;
            }
            break;
        }
        case WORK_SET_PIN: {
            bool ok = Vault.setPin(_pin);
            clearPinBuffers();
            if (ok) {
                computeFingerprints();
                resetListSelection(0);
                showMessage(MSG_OK, "PIN created",
                            Vault.hardwareBound() ? "Vault bound to this chip" : "Software protection only",
                            ST_BACKUP_NOTICE, 1800);
            } else {
                showMessage(MSG_ERROR, "Setup failed", "Could not write vault", ST_LOCKED);
            }
            break;
        }
        case WORK_CHANGE_PIN: {
            UnlockResult r = Vault.changePin(_pinOld, _pin);
            clearPinBuffers();
            resetListSelection(0);
            switch (r) {
                case UNLOCK_OK:
                    showMessage(MSG_OK, "PIN changed", "Use the new PIN from now on", ST_SETTINGS);
                    break;
                case UNLOCK_WRONG_PIN:
                    snprintf(sub, sizeof(sub), "Wrong current PIN, %d left", Vault.remainingAttempts());
                    showMessage(MSG_ERROR, "PIN not changed", sub, ST_SETTINGS, 1800);
                    break;
                case UNLOCK_THROTTLED:
                    showMessage(MSG_WARN, "Please wait", "Too many attempts", ST_SETTINGS);
                    break;
                case UNLOCK_WIPED:
                    computeFingerprints();
                    showMessage(MSG_ERROR, "Vault wiped", "Attempt limit reached", ST_LOCKED, 3500);
                    break;
                default:
                    showMessage(MSG_ERROR, "PIN not changed", "Storage error", ST_SETTINGS);
                    break;
            }
            break;
        }
        case WORK_DELETE_KEY:
            if (Vault.deleteKey(_actionSlot)) {
                computeFingerprints();
                resetListSelection(0);
                showMessage(MSG_OK, "Key deleted", "Erased from flash", ST_KEYS);
            } else {
                showMessage(MSG_ERROR, "Failed", "Could not delete key", ST_KEY_ACTIONS);
            }
            break;
        case WORK_DELETE_PASSKEY:
            resetListSelection(0);
            if (Vault.deletePasskey(_confirmPasskey)) {
                showMessage(MSG_OK, "Passkey deleted", "Erased from flash", ST_PASSKEYS);
            } else {
                showMessage(MSG_ERROR, "Failed", "Could not delete passkey", ST_PASSKEYS);
            }
            _confirmPasskey = nullptr;
            break;
        case WORK_RESET_PASSKEYS:
            resetListSelection(2);
            if (Vault.resetFido()) {
                showMessage(MSG_OK, "Passkeys reset", "All FIDO2 credentials revoked", ST_SETTINGS, 1800);
            } else {
                showMessage(MSG_ERROR, "Failed", "Could not reset passkeys", ST_SETTINGS);
            }
            break;
        case WORK_FACTORY_RESET:
            Vault.factoryReset();
            computeFingerprints();
            clearPinBuffers();
            resetListSelection(0);
            showMessage(MSG_OK, "Device erased", "All keys destroyed", ST_LOCKED, 2500);
            break;
    }
}

void UserInterface::finishGenerating() {
    if (Vault.createKey(_name)) {
        computeFingerprints();
        resetListSelection(visibleOfSlot(Vault.activeSlot()));
        showMessage(MSG_OK, "Key created", _name, ST_KEYS);
    } else {
        showMessage(MSG_ERROR, "Failed", "Could not create key", ST_KEYS);
    }
    sodium_memzero(_name, sizeof(_name));
    _nameLen = 0;
}

void UserInterface::onKeys(ButtonEvent e) {
    int count = Vault.keyCount();
    int n = count + 3;
    switch (e) {
        case BTN_LEFT_CLICK:  _sel = (_sel + n - 1) % n; break;
        case BTN_RIGHT_CLICK: _sel = (_sel + 1) % n; break;
        case BTN_BOTH_HOLD:
            Vault.lock();
            showMessage(MSG_OK, "Vault locked", "Keys cleared from RAM", ST_LOCKED, 1100);
            return;
        case BTN_BOTH_CLICK:
            if (_sel < count) {
                _actionSlot = Vault.slotForVisible(_sel);
                resetListSelection(0);
                go(ST_KEY_ACTIONS);
            } else if (_sel == count) {
                if (count >= MAX_KEYS) {
                    showMessage(MSG_WARN, "Vault full", "Maximum of 8 keys", ST_KEYS);
                } else {
                    sodium_memzero(_name, sizeof(_name));
                    _nameLen = 0;
                    _charCursor = 0;
                    _charWheel = 0;
                    go(ST_NAME);
                }
            } else if (_sel == count + 1) {
                resetListSelection(0);
                go(ST_SETTINGS);
            } else {
                Vault.lock();
                showMessage(MSG_OK, "Vault locked", "Keys cleared from RAM", ST_LOCKED, 1100);
            }
            return;
        default: break;
    }
    _dirty = true;
}

void UserInterface::onKeyActions(ButtonEvent e) {
    const int n = 4;
    const VaultKey *k = Vault.keyAtSlot(_actionSlot);
    if (!k) { go(ST_KEYS); return; }
    switch (e) {
        case BTN_LEFT_CLICK:  _sel = (_sel + n - 1) % n; break;
        case BTN_RIGHT_CLICK: _sel = (_sel + 1) % n; break;
        case BTN_BOTH_HOLD:
            resetListSelection(visibleOfSlot(_actionSlot));
            go(ST_KEYS);
            return;
        case BTN_BOTH_CLICK:
            if (_sel == 0) {
                Vault.setActiveSlot(_actionSlot);
                resetListSelection(visibleOfSlot(_actionSlot));
                showMessage(MSG_OK, "Active key", k->name, ST_KEYS, 1100);
            } else if (_sel == 1) {
                go(ST_FINGERPRINT);
            } else if (_sel == 2) {
                openConfirm(CONFIRM_DELETE_KEY, ST_KEY_ACTIONS);
            } else {
                resetListSelection(visibleOfSlot(_actionSlot));
                go(ST_KEYS);
            }
            return;
        default: break;
    }
    _dirty = true;
}

void UserInterface::onConfirm(ButtonEvent e) {
    switch (e) {
        case BTN_LEFT_CLICK: case BTN_RIGHT_CLICK:
            _confirmChoice ^= 1;
            break;
        case BTN_BOTH_HOLD:
            go(_confirmReturn);
            return;
        case BTN_BOTH_CLICK:
            if (_confirmChoice != 1) {
                go(_confirmReturn);
                return;
            }
            switch (_confirmAction) {
                case CONFIRM_DELETE_KEY:     startWork(WORK_DELETE_KEY); break;
                case CONFIRM_DELETE_PASSKEY: startWork(WORK_DELETE_PASSKEY); break;
                case CONFIRM_RESET_PASSKEYS: startWork(WORK_RESET_PASSKEYS); break;
                case CONFIRM_FACTORY_RESET:  startWork(WORK_FACTORY_RESET); break;
            }
            return;
        default: break;
    }
    _dirty = true;
}

void UserInterface::onSettings(ButtonEvent e) {
    const int n = 6;
    switch (e) {
        case BTN_LEFT_CLICK:  _sel = (_sel + n - 1) % n; break;
        case BTN_RIGHT_CLICK: _sel = (_sel + 1) % n; break;
        case BTN_BOTH_HOLD:
            resetListSelection(Vault.keyCount() + 1);
            go(ST_KEYS);
            return;
        case BTN_BOTH_CLICK:
            switch (_sel) {
                case 0: startPin(PIN_CHANGE_OLD); break;
                case 1:
                    if (Vault.activeSlot() < 0) {
                        showMessage(MSG_WARN, "No active key", "Create or select a key first", ST_SETTINGS);
                    } else {
                        resetListSelection(0);
                        go(ST_PASSKEYS);
                    }
                    break;
                case 2: openConfirm(CONFIRM_RESET_PASSKEYS, ST_SETTINGS); break;
                case 3: openConfirm(CONFIRM_FACTORY_RESET, ST_SETTINGS); break;
                case 4: go(ST_ABOUT); break;
                default:
                    resetListSelection(Vault.keyCount() + 1);
                    go(ST_KEYS);
                    break;
            }
            return;
        default: break;
    }
    _dirty = true;
}

void UserInterface::onPasskeys(ButtonEvent e) {
    int count = Vault.passkeyCount(Vault.activeSlot());
    int n = count + 1;
    switch (e) {
        case BTN_LEFT_CLICK:  _sel = (_sel + n - 1) % n; break;
        case BTN_RIGHT_CLICK: _sel = (_sel + 1) % n; break;
        case BTN_BOTH_HOLD:
            resetListSelection(1);
            go(ST_SETTINGS);
            return;
        case BTN_BOTH_CLICK:
            if (_sel < count) {
                _confirmPasskey = Vault.passkeyAt(Vault.activeSlot(), _sel);
                if (_confirmPasskey) openConfirm(CONFIRM_DELETE_PASSKEY, ST_PASSKEYS);
            } else {
                resetListSelection(1);
                go(ST_SETTINGS);
            }
            return;
        default: break;
    }
    _dirty = true;
}

void UserInterface::onName(ButtonEvent e) {
    switch (e) {
        case BTN_LEFT_CLICK:  _charCursor = (_charCursor + CHAR_N - 1) % CHAR_N; break;
        case BTN_RIGHT_CLICK: _charCursor = (_charCursor + 1) % CHAR_N; break;
        case BTN_BOTH_HOLD:
            go(ST_KEYS);
            return;
        case BTN_BOTH_CLICK:
            if (_charCursor < CHARSET_LEN) {
                if (_nameLen < KEY_NAME_MAX_LEN) {
                    _name[_nameLen++] = CHARSET[_charCursor];
                    _name[_nameLen] = 0;
                }
            } else if (_charCursor == CHARSET_LEN) {
                if (_nameLen > 0) _name[--_nameLen] = 0;
            } else if (_nameLen > 0) {
                go(ST_GENERATING);
                return;
            }
            break;
        default: break;
    }
    _dirty = true;
}

int UserInterface::signOptionCount() const {
    return (_prompt.accountCount > 1 ? _prompt.accountCount : 1) + 1;
}

const char *UserInterface::signOptionLabel(int idx, char *buf, size_t bufLen) const {
    if (idx == signOptionCount() - 1) return "Reject";
    if (_prompt.accountCount > 1) {
        const char *name = _prompt.accounts[idx][0] ? _prompt.accounts[idx] : "(unnamed)";
        snprintf(buf, bufLen, "Sign in as %s", name);
        return buf;
    }
    switch (_prompt.kind) {
        case PROMPT_SSH_LOGIN:          return "Approve login";
        case PROMPT_PASSKEY_CREATE:     return "Create passkey";
        case PROMPT_PASSKEY_USE:        return "Sign in";
        case PROMPT_SK_CREATE:          return "Create SSH key";
        case PROMPT_SK_USE:             return "Approve";
        case PROMPT_ALREADY_REGISTERED: return "OK";
        case PROMPT_FIDO_RESET:         return "Reset all passkeys";
    }
    return "Approve";
}

void UserInterface::onSign(ButtonEvent e) {
    if ((int32_t)(millis() - _signArmedAt) < 0) return;
    if (_btn && (int32_t)(_btn->gestureStart() - _signArmedAt) < 0) return;

    int rejectIdx = signOptionCount() - 1;
    switch (e) {
        case BTN_LEFT_CLICK:
            if (_signChoice > 0) _signChoice--;
            break;
        case BTN_RIGHT_CLICK:
            if (_signChoice < rejectIdx) _signChoice++;
            break;
        case BTN_BOTH_CLICK:
            if (_signChoice == rejectIdx) {
                _signDecision = SIGN_REJECTED;
                showMessage(MSG_ERROR, "Rejected", "Nothing was signed", _signReturn, 1100);
            } else {
                _signAccount = _prompt.accountCount > 1 ? _signChoice : 0;
                _signDecision = SIGN_APPROVED;
                showMessage(MSG_OK, "Approved", "Signature sent", _signReturn, 1000);
            }
            return;
        case BTN_BOTH_HOLD:
            _signDecision = SIGN_REJECTED;
            showMessage(MSG_ERROR, "Rejected", "Nothing was signed", _signReturn, 1100);
            return;
        default: break;
    }
    _dirty = true;
}

void UserInterface::update(ButtonEvent e) {
    uint32_t now = millis();

    if (isUnlockedState(_state) && !Vault.isUnlocked()) go(ST_LOCKED);
    if (_state == ST_PIN && _pinMode >= PIN_CHANGE_OLD && !Vault.isUnlocked()) {
        clearPinBuffers();
        go(ST_LOCKED);
    }

    switch (_state) {
        case ST_BOOT:
            if (now - _stateSince >= BOOT_MS) {
                go(ST_LOCKED);
                if (_unlockReason[0]) requestUnlock(_unlockReason);
            }
            break;
        case ST_MESSAGE:
            if (now - _stateSince >= _msgDuration) {
                UiState next = _msgNext;
                if (isUnlockedState(next) && !Vault.isUnlocked()) next = ST_LOCKED;
                if (next == ST_PIN && Vault.throttleRemainingMs() > 0) next = ST_LOCKED;
                if (next == ST_PIN && _pinMode >= PIN_CHANGE_OLD && !Vault.isUnlocked()) next = ST_LOCKED;
                go(next);
            }
            break;
        case ST_WORKING:
            if (_lastFrame > _stateSince) runWork();
            break;
        case ST_GENERATING:
            if (now - _stateSince >= GEN_MS) finishGenerating();
            break;
        case ST_SIGN:
            if ((int32_t)(now - _signDeadline) >= 0) {
                _signDecision = SIGN_TIMEOUT;
                showMessage(MSG_WARN, "Timed out", "Nothing was signed", _signReturn);
            }
            break;
        default: break;
    }

    if (e != BTN_NONE) {
        if (Vault.isUnlocked()) Vault.touch();
        switch (_state) {
            case ST_LOCKED:         onLocked(e); break;
            case ST_PIN:            onPin(e); break;
            case ST_KEYS:           onKeys(e); break;
            case ST_KEY_ACTIONS:    onKeyActions(e); break;
            case ST_FINGERPRINT:    if (e == BTN_BOTH_CLICK || e == BTN_BOTH_HOLD) go(ST_KEY_ACTIONS); break;
            case ST_CONFIRM:        onConfirm(e); break;
            case ST_NAME:           onName(e); break;
            case ST_SIGN:           onSign(e); break;
            case ST_SETTINGS:       onSettings(e); break;
            case ST_PASSKEYS:       onPasskeys(e); break;
            case ST_ABOUT:
                if (e == BTN_BOTH_CLICK || e == BTN_BOTH_HOLD) { resetListSelection(4); go(ST_SETTINGS); }
                break;
            case ST_BACKUP_NOTICE:
                if (e == BTN_BOTH_CLICK) { resetListSelection(0); go(ST_KEYS); }
                break;
            case ST_MESSAGE:
                if (now - _stateSince > 350) _stateSince = now - _msgDuration;
                break;
            default: break;
        }
    }

    if ((_dirty || animating()) && (now - _lastFrame >= FRAME_MS)) {
        _dirty = false;
        render(now);
        _lastFrame = millis();
    }
}

void UserInterface::render(uint32_t now) {
    g_settling = false;
    g->fillScreen(C_BG);

    switch (_state) {
        case ST_BOOT:           drawBoot(now); break;
        case ST_LOCKED:         drawLocked(now); break;
        case ST_PIN:            drawPin(now); break;
        case ST_WORKING:
            switch (_work) {
                case WORK_UNLOCK:         drawVerifying(now, "Verifying PIN", "Unwrapping vault key"); break;
                case WORK_SET_PIN:        drawVerifying(now, "Securing vault", "Binding key to this chip"); break;
                case WORK_CHANGE_PIN:     drawVerifying(now, "Changing PIN", "Re-wrapping vault key"); break;
                case WORK_FACTORY_RESET:  drawVerifying(now, "Erasing device", "Scrubbing flash"); break;
                default:                  drawVerifying(now, "Erasing", "Scrubbing flash"); break;
            }
            break;
        case ST_MESSAGE:        drawMessage(now); break;
        case ST_KEYS:           drawKeys(now); break;
        case ST_KEY_ACTIONS:    drawKeyActions(now); break;
        case ST_FINGERPRINT:    drawFingerprint(now); break;
        case ST_CONFIRM:        drawConfirm(now); break;
        case ST_NAME:           drawName(now); break;
        case ST_GENERATING:     drawVerifying(now, "Generating key", "Ed25519 via hardware TRNG"); break;
        case ST_SIGN:           drawSign(now); break;
        case ST_SETTINGS:       drawSettings(now); break;
        case ST_PASSKEYS:       drawPasskeys(now); break;
        case ST_ABOUT:          drawAbout(now); break;
        case ST_BACKUP_NOTICE:  drawBackupNotice(now); break;
    }

    uint32_t el = now - _stateSince;
    if (_state != ST_BOOT && el < FADE_MS) {
        fadeFramebuffer((uint8_t)(6 + (26 * easeOut((float)el / FADE_MS))));
    }
    g->flush();
}

void UserInterface::drawHeader(const char *title, uint16_t accent, const char *chip) {
    g->fillRect(0, 0, CONTENT_W, 27, C_BG);
    g->fillCircle(13, 13, 7, blend(accent, C_BG, 40));
    g->fillCircle(13, 13, 4, accent);
    font(F_B9);
    text(26, 19, title, C_TEXT);
    if (chip && *chip) {
        smallFont();
        int w = strlen(chip) * 6 + 14;
        g->fillRoundRect(CONTENT_W - 8 - w, 6, w, 15, 7, C_SURF2);
        text(CONTENT_W - 8 - w + 7, 10, chip, C_MUTED);
    }
    g->drawFastHLine(0, 27, CONTENT_W, C_LINE);
}

void UserInterface::drawHints(const char *up, const char *both, const char *down, const char *hold) {
    uint16_t *fb = g->getFramebuffer();
    if (!fb) return;

    static uint16_t saveBuf[H * RAIL_W];
    for (int v = 0; v < RAIL_W; v++) {
        memcpy(&saveBuf[v * H], &fb[v * W], H * sizeof(uint16_t));
    }

    g->fillRect(0, 0, H, RAIL_W, C_SURF);
    g->drawFastHLine(0, RAIL_W - 1, H, C_LINE);

    uint8_t hp = _btn ? _btn->holdProgress() : 0;
    if (hold && hp > 0) {
        int fillW = (H * hp) / 255;
        g->fillRect(0, 0, fillW, RAIL_W - 1, blend(C_RED, C_SURF, 165));
        smallFont();
        char buf[40];
        snprintf(buf, sizeof(buf), "Hold: %s", hold);
        textCenter(H / 2, 6, buf, C_TEXT);
    } else {
        smallFont();
        if (up && *up) {
            int upW = (int)strlen(up) * 6 + 16;
            g->fillRoundRect(2, 2, upW < 42 ? 42 : upW, 15, 5, C_SURF2);
            g->fillTriangle(6, 9, 10, 6, 10, 12, C_CYAN);
            text(14, 6, up, C_TEXT);
        }
        if (down && *down) {
            g->fillRoundRect(H - 44, 2, 42, 15, 5, C_SURF2);
            textRight(H - 14, 6, down, C_TEXT);
            g->fillTriangle(H - 7, 9, H - 11, 6, H - 11, 12, C_CYAN);
        }
        if (both && *both) {
            g->fillRoundRect(46, 2, 78, 15, 5, C_SURF2);
            g->drawRoundRect(46, 2, 78, 15, 5, blend(C_CYAN, C_SURF2, 130));
            g->fillRoundRect(48, 4, 16, 11, 3, C_CYAN);
            g->fillCircle(53, 9, 2, C_BG);
            g->fillCircle(59, 9, 2, C_BG);
            textCenter(94, 6, both, C_TEXT);
        }
    }

    for (int v = 0; v < RAIL_W; v++) {
        int dstX = W - 1 - v;
        for (int u = 0; u < H; u++) {
            fb[u * W + dstX] = fb[v * W + u];
        }
        memcpy(&fb[v * W], &saveBuf[v * H], H * sizeof(uint16_t));
    }
}

void UserInterface::drawWheel(const char *const *items, int count, float pos, int cursor, int cx, bool okEnabled) {
    const int cy = 98;
    const int spacing = 29;

    g->fillRoundRect(cx - 26, 33, 52, 130, 12, C_SURF);
    g->drawRoundRect(cx - 26, 33, 52, 130, 12, C_LINE);

    g->fillRoundRect(cx - 24, cy - 17, 48, 34, 10, blend(C_CYAN, C_BG, 45));
    g->fillRoundRect(cx - 22, cy - 15, 44, 30, 8, C_CYAN);

    for (int i = 0; i < count; i++) {
        float d = wrapDelta(i - pos, count);
        float ad = fabsf(d);
        if (ad > 2.1f) continue;
        int y = cy + (int)(d * spacing);
        const char *s = items[i];
        bool special = strlen(s) > 1;

        uint16_t base = C_TEXT;
        if (!strcmp(s, "DEL")) base = C_RED;
        if (!strcmp(s, "OK"))  base = okEnabled ? C_GREEN : C_MUTED;

        if (ad < 0.45f) {
            font(special ? F_B9 : F_B12);
            textCenter(cx, y + (special ? 5 : 7), s, C_BG);
        } else {
            uint8_t a = (uint8_t)(255 * clamp01(1.15f - ad / 2.2f));
            font(F_B9);
            textCenter(cx, y + 5, s, blend(base, C_SURF, a));
        }
    }

    g->fillTriangle(cx, 37, cx - 4, 41, cx + 4, 41, C_MUTED);
    g->fillTriangle(cx, 159, cx - 4, 155, cx + 4, 155, C_MUTED);
    (void)cursor;
}

void UserInterface::drawList(const char *const *labels, const char *const *subs, const uint16_t *colors,
                             int count, int activeIdx, int top, int rowH, int visible) {
    int maxScroll = count > visible ? count - visible : 0;
    int scrollTarget = _sel - 1;
    if (scrollTarget < 0) scrollTarget = 0;
    if (scrollTarget > maxScroll) scrollTarget = maxScroll;
    g_settling |= approach(_selAnim, (float)_sel);
    g_settling |= approach(_scrollAnim, (float)scrollTarget);

    int sy = top + (int)((_selAnim - _scrollAnim) * rowH);
    g->fillRoundRect(8, sy + 2, CONTENT_W - 20, rowH - 4, 9, C_SURF2);
    g->fillRoundRect(8, sy + 2, 4, rowH - 4, 2, C_CYAN);

    for (int i = 0; i < count; i++) {
        int y = top + (int)((i - _scrollAnim) * rowH);
        if (y + rowH < top - 4 || y > top + visible * rowH + 4) continue;
        bool sel = (i == _sel);
        uint16_t c = colors ? colors[i] : C_TEXT;
        bool hasSub = subs && subs[i] && *subs[i];

        font(F_B9);
        text(20, y + (hasSub ? 19 : 27), labels[i], sel ? c : blend(c, C_BG, 170));
        if (hasSub) {
            smallFont();
            text(20, y + 26, subs[i], sel ? C_MUTED : blend(C_MUTED, C_BG, 150));
        }
        if (i == activeIdx) {
            g->fillRoundRect(CONTENT_W - 76, y + 13, 58, 16, 8, blend(C_GREEN, C_BG, 60));
            g->fillCircle(CONTENT_W - 67, y + 21, 3, C_GREEN);
            smallFont();
            text(CONTENT_W - 60, y + 17, "ACTIVE", C_GREEN);
        }
    }

    if (count > visible) {
        int trackH = visible * rowH - 8;
        int thumbH = trackH * visible / count;
        int thumbY = top + 4 + (int)((trackH - thumbH) * (_scrollAnim / maxScroll));
        g->fillRoundRect(CONTENT_W - 7, top + 4, 3, trackH, 1, C_SURF2);
        g->fillRoundRect(CONTENT_W - 7, thumbY, 3, thumbH, 1, C_CYAN);
    }
}

void UserInterface::drawBoot(uint32_t now) {
    float t = (float)(now - _stateSince) / BOOT_MS;
    int cx = 70, cy = 78;

    float ring = easeOut(clamp01(t / 0.45f));
    g->fillArc(cx, cy, 40, 36, 0, 360, C_SURF2);
    if (ring > 0) g->fillArc(cx, cy, 40, 36, -90, -90 + 360 * ring, C_CYAN);
    float open = 1.0f - easeOut(clamp01((t - 0.40f) / 0.15f));
    lockIcon(cx, cy - 4, C_CYAN, C_BG, open);

    float ta = easeOut(clamp01((t - 0.35f) / 0.30f));
    font(F_B18);
    text(128 + (int)((1 - ta) * 16), 78, "Zeru Vault", blend(C_TEXT, C_BG, (uint8_t)(255 * ta)));
    float sa = easeOut(clamp01((t - 0.50f) / 0.30f));
    font(F_REG);
    text(130, 102, "Hardware key vault", blend(C_MUTED, C_BG, (uint8_t)(255 * sa)));

    float pb = easeOut(clamp01(t / 0.95f));
    g->fillRoundRect(40, 140, W - 80, 4, 2, C_SURF2);
    g->fillRoundRect(40, 140, (int)((W - 80) * pb), 4, 2, C_CYAN);
}

void UserInterface::drawLocked(uint32_t now) {
    drawHeader("Zeru Vault", C_RED, "FIDO2+SSH");

    int cx = 62, cy = 96;
    float p = pulse(now, 0.6f);
    g->fillCircle(cx, cy, 40 + (int)(4 * p), blend(C_RED, C_BG, (uint8_t)(18 + 22 * p)));
    g->fillCircle(cx, cy, 35, C_SURF);
    g->drawCircle(cx, cy, 35, blend(C_RED, C_SURF, 90));
    lockIcon(cx, cy - 6, C_RED, C_SURF, 0);

    bool firstUse = !Vault.isPinSet();
    uint32_t wait = Vault.throttleRemainingMs();

    font(F_B18);
    text(116, 86, firstUse ? "Welcome" : "Locked", C_TEXT);
    font(F_REG);
    char line[40];
    if (wait > 0) {
        snprintf(line, sizeof(line), "Wait %lus", (unsigned long)((wait + 999) / 1000));
        text(117, 110, line, C_AMBER);
    } else if (firstUse) {
        text(117, 110, "Create a PIN (6-8)", C_MUTED);
    } else {
        text(117, 110, "Enter your PIN", C_MUTED);
    }
    if (!firstUse) {
        int left = Vault.remainingAttempts();
        if (left < PIN_MAX_ATTEMPTS) {
            smallFont();
            snprintf(line, sizeof(line), "%d attempts remaining", left);
            text(117, 122, line, C_AMBER);
        }
    }
    if (_unlockReason[0]) {
        smallFont();
        text(117, 138, "Request waiting:", C_AMBER);
        text(117, 148, _unlockReason, C_TEXT);
    }

    drawHints("", wait > 0 ? "" : (firstUse ? "Setup" : "Unlock"), "", firstUse ? nullptr : "factory reset");
}

void UserInterface::drawPin(uint32_t now) {
    const char *title = "Enter PIN";
    switch (_pinMode) {
        case PIN_UNLOCK:         title = "Enter PIN"; break;
        case PIN_NEW:            title = "Create PIN"; break;
        case PIN_CONFIRM:        title = "Confirm PIN"; break;
        case PIN_CHANGE_OLD:     title = "Current PIN"; break;
        case PIN_CHANGE_NEW:     title = "New PIN"; break;
        case PIN_CHANGE_CONFIRM: title = "Confirm new PIN"; break;
    }
    const int minLen = pinMinLen();
    char chip[12];
    snprintf(chip, sizeof(chip), "%d/%d", _pinLen, PIN_MAX_LEN);
    drawHeader(title, C_AMBER, chip);

    smallFont();
    if (_pinMode == PIN_UNLOCK && _unlockReason[0]) {
        text(14, 40, _unlockReason, C_AMBER);
    } else {
        char hint[40];
        snprintf(hint, sizeof(hint), "PIN CODE (%d TO %d DIGITS)", minLen, PIN_MAX_LEN);
        text(14, 40, hint, C_MUTED);
    }
    g->fillRoundRect(12, 54, 210, 48, 10, C_SURF);
    g->drawRoundRect(12, 54, 210, 48, 10, C_LINE);

    const int gap = 23;
    int x0 = 12 + 105 - (PIN_MAX_LEN - 1) * gap / 2;
    for (int i = 0; i < PIN_MAX_LEN; i++) {
        int x = x0 + i * gap, y = 78;
        if (i < _pinLen) {
            float pop = (i == _pinLen - 1) ? easeBack(clamp01((now - _pinPopAt) / 220.0f)) : 1.0f;
            int r = 3 + (int)(4 * pop);
            g->fillCircle(x, y, r + 3, blend(C_CYAN, C_BG, 45));
            g->fillCircle(x, y, r, C_CYAN);
        } else {
            g->drawCircle(x, y, 5, i < minLen ? C_MUTED : C_LINE);
        }
    }

    smallFont();
    text(14, 118, "Use Up / Down to spin drum", C_MUTED);
    text(14, 132, _pinLen >= minLen ? "Select OK to confirm PIN" : "Hold both buttons to go back",
         _pinLen >= minLen ? C_GREEN : C_LINE);

    g_settling |= approachWrap(_pinWheel, _pinCursor, PIN_N);
    drawWheel(PIN_ITEMS, PIN_N, _pinWheel, _pinCursor, 261, _pinLen >= minLen);

    bool redo = _pinMode == PIN_CONFIRM || _pinMode == PIN_CHANGE_CONFIRM;
    drawHints("Up", "Select", "Down", redo ? "redo" : "back");
}

void UserInterface::drawVerifying(uint32_t now, const char *title, const char *sub) {
    spinner(W / 2, 70, now, C_CYAN);
    font(F_B12);
    textCenter(W / 2, 124, title, C_TEXT);
    smallFont();
    textCenter(W / 2, 136, sub, C_MUTED);
}

void UserInterface::drawMessage(uint32_t now) {
    uint32_t el = now - _stateSince;
    int shake = 0;
    if (_msgKind == MSG_ERROR && el < 450) {
        shake = (int)(sinf(el * 0.07f) * 9 * (1.0f - el / 450.0f));
    }
    statusIcon(W / 2 + shake, 66, _msgKind, clamp01(el / 420.0f));

    float ta = easeOut(clamp01(((int32_t)el - 120) / 250.0f));
    font(F_B12);
    textCenter(W / 2, 126, _msgTitle, blend(C_TEXT, C_BG, (uint8_t)(255 * ta)));
    smallFont();
    textCenter(W / 2, 138, _msgSub, blend(C_MUTED, C_BG, (uint8_t)(255 * ta)));

    float pr = clamp01((float)el / _msgDuration);
    uint16_t c = _msgKind == MSG_OK ? C_GREEN : (_msgKind == MSG_ERROR ? C_RED : C_AMBER);
    g->fillRect(0, H - 3, (int)(W * pr), 3, blend(c, C_BG, 140));
}

void UserInterface::drawKeys(uint32_t now) {
    int count = Vault.keyCount();
    int n = count + 3;
    const char *labels[MAX_KEYS + 3];
    const char *subs[MAX_KEYS + 3];
    uint16_t colors[MAX_KEYS + 3];
    char shortFp[MAX_KEYS][28];
    int activeIdx = -1;

    for (int i = 0; i < count; i++) {
        int slot = Vault.slotForVisible(i);
        const VaultKey *k = Vault.keyAtSlot(slot);
        labels[i] = k ? k->name : "?";
        snprintf(shortFp[i], sizeof(shortFp[i]), "%.21s...", _fingerprints[slot]);
        subs[i] = shortFp[i];
        colors[i] = C_TEXT;
        if (slot == Vault.activeSlot()) activeIdx = i;
    }
    labels[count] = "+ New key";     subs[count] = "Generate on-device Ed25519"; colors[count] = C_CYAN;
    labels[count + 1] = "Settings";   subs[count + 1] = "PIN, passkeys, reset, about"; colors[count + 1] = C_TEXT;
    labels[count + 2] = "Lock vault"; subs[count + 2] = "Wipe keys from RAM";          colors[count + 2] = C_RED;

    if (_sel >= n) _sel = n - 1;
    drawList(labels, subs, colors, n, activeIdx, 31, 44, 3);

    char chip[16];
    snprintf(chip, sizeof(chip), "%d/%d", count, MAX_KEYS);
    drawHeader("Keys", C_GREEN, chip);
    drawHints("Up", "Open", "Down", "lock");
    (void)now;
}

void UserInterface::drawKeyActions(uint32_t now) {
    const VaultKey *k = Vault.keyAtSlot(_actionSlot);
    static const char *labels[] = {"Use this key", "View fingerprint", "Delete key", "Back"};
    static const char *subs[]   = {"Expose only this key to host", "Compare with ssh-keygen -l",
                                   "Permanently erase", ""};
    static const uint16_t colors[] = {C_GREEN, C_TEXT, C_RED, C_MUTED};
    int active = (_actionSlot == Vault.activeSlot()) ? 0 : -1;
    drawList(labels, subs, colors, 4, active, 31, 44, 3);
    drawHeader(k ? k->name : "Key", C_CYAN, "ACTIONS");
    drawHints("Up", "Select", "Down", "back");
    (void)now;
}

void UserInterface::drawFingerprint(uint32_t now) {
    const VaultKey *k = Vault.keyAtSlot(_actionSlot);
    drawHeader(k ? k->name : "Key", C_CYAN, "SHA256");
    if (k) {
        const char *fp = _fingerprints[_actionSlot] + 7;
        smallFont();
        text(16, 40, "ssh-ed25519  SHA256:", C_MUTED);
        font(F_MONO);
        char line[16];
        int len = strlen(fp);
        for (int i = 0, row = 0; i < len; i += 15, row++) {
            snprintf(line, sizeof(line), "%.15s", fp + i);
            text(16, 74 + row * 26, line, C_CYAN);
        }
    }
    drawHints("", "Back", "", "back");
    (void)now;
}

void UserInterface::drawName(uint32_t now) {
    char chip[12];
    snprintf(chip, sizeof(chip), "%d/%d", _nameLen, KEY_NAME_MAX_LEN);
    drawHeader("Key name", C_CYAN, chip);

    smallFont();
    text(14, 40, "KEY IDENTIFIER", C_MUTED);
    g->fillRoundRect(12, 54, 210, 42, 9, C_SURF);
    g->drawRoundRect(12, 54, 210, 42, 9, C_LINE);
    font(F_MONO);
    int x = 22;
    if (_nameLen > 0) {
        text(x, 81, _name, C_TEXT);
        x += textWidth(_name) + 3;
    } else {
        smallFont();
        text(x, 71, "e.g. SRV_PROD, GITHUB", C_LINE);
    }
    if ((now / 530) % 2 == 0 && x < 214) g->fillRect(x, 65, 2, 18, C_CYAN);

    smallFont();
    text(14, 116, "Use Up / Down to spin drum", C_MUTED);
    text(14, 130, _nameLen > 0 ? "Select OK to generate key" : "Hold both buttons to cancel",
         _nameLen > 0 ? C_GREEN : C_LINE);

    g_settling |= approachWrap(_charWheel, _charCursor, CHAR_N);
    drawWheel(CHAR_ITEMS, CHAR_N, _charWheel, _charCursor, 261, _nameLen > 0);

    drawHints("Up", "Insert", "Down", "cancel");
}

void UserInterface::drawConfirm(uint32_t now) {
    const char *title = "Confirm", *name = "", *line1 = "", *line2 = "", *danger = "Confirm";
    char nameBuf[RP_ID_MAX_LEN + 1];
    char lineBuf[48];
    switch (_confirmAction) {
        case CONFIRM_DELETE_KEY: {
            const VaultKey *k = Vault.keyAtSlot(_actionSlot);
            title = "Delete key"; name = k ? k->name : "?";
            line1 = "Key and its passkeys are erased"; line2 = "forever. Cannot be recovered.";
            danger = "Delete key";
            break;
        }
        case CONFIRM_DELETE_PASSKEY: {
            const Passkey *p = _confirmPasskey;
            snprintf(nameBuf, sizeof(nameBuf), "%s", (p && p->rpId[0]) ? p->rpId : "(site from v1)");
            name = nameBuf;
            snprintf(lineBuf, sizeof(lineBuf), "Account: %s", (p && p->userName[0]) ? p->userName : "-");
            line1 = lineBuf; line2 = "You may lose access to it.";
            title = "Delete passkey"; danger = "Delete passkey";
            break;
        }
        case CONFIRM_RESET_PASSKEYS:
            title = "Reset passkeys"; name = "All FIDO2 credentials";
            line1 = "Every passkey and ssh-sk key"; line2 = "on this device stops working.";
            danger = "Reset passkeys";
            break;
        case CONFIRM_FACTORY_RESET:
            title = "Factory reset"; name = "Erase everything";
            line1 = "All keys, passkeys and the PIN"; line2 = "are destroyed permanently.";
            danger = "Erase device";
            break;
    }
    drawHeader(title, C_RED, "IRREVERSIBLE");

    statusIcon(42, 66, MSG_WARN, 1.0f);
    char shownName[RP_ID_MAX_LEN + 3];
    font(F_B12);
    if (textWidth(name) > CONTENT_W - 96) font(F_B9);
    fitLeftEllipsis(name, shownName, sizeof(shownName), CONTENT_W - 96);
    text(84, 58, shownName, C_TEXT);
    smallFont();
    text(84, 70, line1, C_MUTED);
    text(84, 80, line2, C_MUTED);

    const int bx = 14, bw = CONTENT_W - 28, bh = 28;
    const int yCancel = 102, yDanger = 134;
    bool sel = _confirmChoice == 1;

    g->fillRoundRect(bx, yCancel, bw, bh, 8, sel ? C_SURF : C_SURF2);
    if (!sel) g->drawRoundRect(bx, yCancel, bw, bh, 8, C_CYAN);
    g->fillRoundRect(bx, yDanger, bw, bh, 8, sel ? C_RED : C_SURF);

    font(F_B9);
    textCenter(bx + bw / 2, yCancel + 19, "Keep / Cancel", sel ? C_MUTED : C_TEXT);
    textCenter(bx + bw / 2, yDanger + 19, danger, sel ? C_BG : blend(C_RED, C_BG, 170));

    drawHints("Up", "Confirm", "Down", "back");
    (void)now;
}

void UserInterface::drawSign(uint32_t now) {
    const char *headerTitle = "Authorize", *fieldLabel = "REQUEST";
    uint16_t accent = C_AMBER;
    switch (_prompt.kind) {
        case PROMPT_SSH_LOGIN:          headerTitle = "SSH login";          fieldLabel = "REMOTE USER"; break;
        case PROMPT_PASSKEY_CREATE:     headerTitle = "Create passkey";     fieldLabel = "WEBSITE"; break;
        case PROMPT_PASSKEY_USE:        headerTitle = "Sign in";            fieldLabel = "WEBSITE"; break;
        case PROMPT_SK_CREATE:          headerTitle = "New SSH sk key";     fieldLabel = "APPLICATION"; break;
        case PROMPT_SK_USE:             headerTitle = "SSH security key";   fieldLabel = "APPLICATION"; break;
        case PROMPT_ALREADY_REGISTERED: headerTitle = "Already registered"; fieldLabel = "WEBSITE"; break;
        case PROMPT_FIDO_RESET:         headerTitle = "Reset passkeys?";    fieldLabel = "REQUESTED BY HOST"; accent = C_RED; break;
    }
    bool armed = (int32_t)(now - _signArmedAt) >= 0;
    int32_t left = (int32_t)(_signDeadline - now);
    if (left < 0) left = 0;
    char chip[16];
    if (armed) snprintf(chip, sizeof(chip), "%lds", (long)((left + 999) / 1000));
    else snprintf(chip, sizeof(chip), "READ FIRST");
    drawHeader(headerTitle, accent, chip);

    const int cw = CONTENT_W - 18;
    const int maxW = cw - 20;
    smallFont();
    text(14, 32, fieldLabel, C_MUTED);

    char shown[RP_ID_MAX_LEN + 3];
    font(F_B18);
    if (textWidth(_prompt.target) > maxW) font(F_B12);
    if (textWidth(_prompt.target) > maxW) font(F_B9);
    fitLeftEllipsis(_prompt.target, shown, sizeof(shown), maxW);
    text(14, 68, shown, C_TEXT);

    smallFont();
    char line[72];
    if (_prompt.accountCount == 1 && _prompt.accounts[0][0]) {
        snprintf(line, sizeof(line), "Account: %s", _prompt.accounts[0]);
        text(14, 76, line, C_MUTED);
    } else if (_prompt.accountCount > 1) {
        snprintf(line, sizeof(line), "%d accounts - pick one below", _prompt.accountCount);
        text(14, 76, line, C_CYAN);
    } else if (_prompt.detail[0]) {
        bool neutral = _prompt.kind == PROMPT_SSH_LOGIN || _prompt.kind == PROMPT_SK_USE || _prompt.kind == PROMPT_SK_CREATE;
        text(14, 76, _prompt.detail, neutral ? C_MUTED : C_AMBER);
    }
    snprintf(line, sizeof(line), "Key: %s", _prompt.keyName);
    text(14, 87, line, C_CYAN);

    int count = signOptionCount();
    int rejectIdx = count - 1;
    int top = _signChoice > count - 2 ? count - 2 : _signChoice;
    if (top < 0) top = 0;
    const int bx = 10, bw = CONTENT_W - 20, bh = 26;
    for (int row = 0; row < 2 && top + row < count; row++) {
        int idx = top + row;
        int y = 100 + row * 30;
        bool sel = idx == _signChoice;
        bool reject = idx == rejectIdx;
        uint16_t c = reject ? C_RED : (_prompt.kind == PROMPT_FIDO_RESET ? C_RED : C_GREEN);
        uint16_t fill = sel ? (armed ? c : blend(c, C_SURF, 120)) : C_SURF;
        g->fillRoundRect(bx, y, bw, bh, 8, fill);
        if (!sel) g->drawRoundRect(bx, y, bw, bh, 8, blend(c, C_SURF, 110));
        char buf[48];
        font(F_B9);
        textCenter(bx + bw / 2, y + 18, signOptionLabel(idx, buf, sizeof(buf)), sel ? C_BG : blend(c, C_BG, 200));
    }
    if (count > 2) {
        if (top > 0) g->fillTriangle(bx + bw - 10, 95, bx + bw - 14, 98, bx + bw - 6, 98, C_MUTED);
        if (top + 2 < count) g->fillTriangle(bx + bw - 10, 162, bx + bw - 14, 159, bx + bw - 6, 159, C_MUTED);
    }

    float frac = (float)left / SIGN_MS;
    g->fillRect(0, H - 3, (int)(CONTENT_W * frac), 3, left < 8000 ? C_RED : C_AMBER);

    if (armed) drawHints("Up", "Confirm", "Down", "reject");
    else drawHints("", "Wait", "", nullptr);
}

void UserInterface::drawSettings(uint32_t now) {
    static const char *labels[] = {"Change PIN", "Passkeys", "Reset passkeys", "Factory reset", "About", "Back"};
    char passkeySub[40];
    const VaultKey *k = Vault.keyAtSlot(Vault.activeSlot());
    if (k) snprintf(passkeySub, sizeof(passkeySub), "%d saved on %s", Vault.passkeyCount(Vault.activeSlot()), k->name);
    else snprintf(passkeySub, sizeof(passkeySub), "No active key");
    const char *subs[] = {"6-8 digits, entered on device", passkeySub, "Revoke all FIDO2 credentials",
                          "Erase keys, passkeys and PIN", "Version and protection", ""};
    static const uint16_t colors[] = {C_TEXT, C_TEXT, C_AMBER, C_RED, C_TEXT, C_MUTED};
    drawList(labels, subs, colors, 6, -1, 31, 44, 3);
    drawHeader("Settings", C_CYAN, "");
    drawHints("Up", "Select", "Down", "back");
    (void)now;
}

void UserInterface::drawPasskeys(uint32_t now) {
    int slot = Vault.activeSlot();
    int count = Vault.passkeyCount(slot);
    const char *labels[MAX_PASSKEYS + 1];
    const char *subs[MAX_PASSKEYS + 1];
    uint16_t colors[MAX_PASSKEYS + 1];
    static char shown[MAX_PASSKEYS][RP_ID_MAX_LEN + 3];
    font(F_B9);
    for (int i = 0; i < count; i++) {
        const Passkey *p = Vault.passkeyAt(slot, i);
        fitLeftEllipsis((p && p->rpId[0]) ? p->rpId : "(site from v1)", shown[i], sizeof(shown[i]), CONTENT_W - 40);
        labels[i] = shown[i];
        subs[i] = (p && p->userName[0]) ? p->userName : "(no account name)";
        colors[i] = C_TEXT;
    }
    labels[count] = "Back";
    subs[count] = count ? "" : "No passkeys on this key";
    colors[count] = C_MUTED;
    if (_sel > count) _sel = count;
    drawList(labels, subs, colors, count + 1, -1, 31, 44, 3);

    const VaultKey *k = Vault.keyAtSlot(slot);
    char chip[24];
    snprintf(chip, sizeof(chip), "%d/%d", count, MAX_PASSKEYS);
    drawHeader(k ? k->name : "Passkeys", C_CYAN, chip);
    drawHints("Up", count ? "Delete" : "Back", "Down", "back");
    (void)now;
}

void UserInterface::drawAbout(uint32_t now) {
    drawHeader("About", C_CYAN, "v" FIRMWARE_VERSION);
    char line[48];
    font(F_B9);
    text(16, 50, "Zeru Vault " FIRMWARE_VERSION, C_TEXT);
    smallFont();
    bool hw = Vault.hardwareBound();
    text(16, 64, hw ? "Protection: eFuse HMAC + PIN" : "Protection: PIN only (no eFuse)", hw ? C_GREEN : C_AMBER);
    snprintf(line, sizeof(line), "Keys %d/%d   Passkeys %d", Vault.keyCount(), MAX_KEYS,
             Vault.passkeyCount(Vault.activeSlot()));
    text(16, 78, line, C_MUTED);
    snprintf(line, sizeof(line), "Auto-lock %lum idle, %luh max",
             (unsigned long)(AUTO_LOCK_IDLE_MS / 60000UL), (unsigned long)(SESSION_MAX_MS / 3600000UL));
    text(16, 92, line, C_MUTED);
    snprintf(line, sizeof(line), "Wipe after %d wrong PINs", PIN_MAX_ATTEMPTS);
    text(16, 106, line, C_MUTED);
    snprintf(line, sizeof(line), "Unlocked for %lu min", (unsigned long)(Vault.sessionMs() / 60000UL));
    text(16, 120, line, C_MUTED);
    text(16, 140, "No backup: register 2 keys", C_AMBER);
    drawHints("", "Back", "", "back");
    (void)now;
}

void UserInterface::drawBackupNotice(uint32_t now) {
    drawHeader("Before you start", C_AMBER, "BACKUP");
    statusIcon(42, 72, MSG_WARN, 1.0f);
    font(F_B9);
    text(84, 52, "Keys never leave", C_TEXT);
    text(84, 70, "this device.", C_TEXT);
    smallFont();
    text(84, 86, "There is no export or backup.", C_MUTED);
    text(14, 112, "Register a SECOND security key on", C_AMBER);
    text(14, 124, "every account, or keep recovery", C_AMBER);
    text(14, 136, "codes, so losing this one is OK.", C_AMBER);
    drawHints("", "Got it", "", nullptr);
    (void)now;
}
