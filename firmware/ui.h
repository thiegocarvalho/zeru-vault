#pragma once
#include <Arduino.h>
#include "buttons.h"
#include "vault.h"

enum UiState {
    ST_BOOT = 0,
    ST_LOCKED,
    ST_PIN,
    ST_WORKING,
    ST_MESSAGE,
    ST_KEYS,
    ST_KEY_ACTIONS,
    ST_FINGERPRINT,
    ST_CONFIRM,
    ST_NAME,
    ST_GENERATING,
    ST_SIGN,
    ST_SETTINGS,
    ST_PASSKEYS,
    ST_ABOUT,
    ST_BACKUP_NOTICE
};

enum SignDecision { SIGN_NONE = 0, SIGN_APPROVED, SIGN_REJECTED, SIGN_TIMEOUT };

enum MsgKind { MSG_OK = 0, MSG_ERROR, MSG_WARN };

enum PromptKind {
    PROMPT_SSH_LOGIN = 0,
    PROMPT_PASSKEY_CREATE,
    PROMPT_PASSKEY_USE,
    PROMPT_SK_CREATE,
    PROMPT_SK_USE,
    PROMPT_ALREADY_REGISTERED,
    PROMPT_FIDO_RESET
};

static constexpr int PROMPT_MAX_ACCOUNTS = 8;

struct SignPrompt {
    PromptKind kind;
    char keyName[KEY_NAME_MAX_LEN + 1];
    char target[RP_ID_MAX_LEN + 1];
    char detail[56];
    char accounts[PROMPT_MAX_ACCOUNTS][USER_NAME_MAX_LEN + 1];
    int  accountCount;
};

class UserInterface {
public:
    void begin(ButtonManager *buttons);
    void update(ButtonEvent evt);

    void requestSignConfirmation(const SignPrompt &prompt);
    void cancelSignConfirmation();
    SignDecision signDecision() const { return _signDecision; }
    int  signAccount() const { return _signAccount; }
    void clearSignDecision() { _signDecision = SIGN_NONE; }

    void requestUnlock(const char *reason);
    void clearUnlockRequest();
    bool takeUnlockDeclined();

    void notifyAutoLocked(const char *reason);
    void notify(MsgKind kind, const char *title, const char *sub);

private:
    ButtonManager *_btn = nullptr;
    UiState  _state = ST_BOOT;
    UiState  _prevState = ST_BOOT;
    uint32_t _stateSince = 0;
    uint32_t _lastFrame = 0;
    bool     _dirty = true;

    enum PinMode { PIN_UNLOCK, PIN_NEW, PIN_CONFIRM, PIN_CHANGE_OLD, PIN_CHANGE_NEW, PIN_CHANGE_CONFIRM };
    PinMode  _pinMode = PIN_UNLOCK;
    char     _pin[PIN_MAX_LEN + 1];
    char     _pinFirst[PIN_MAX_LEN + 1];
    char     _pinOld[PIN_MAX_LEN + 1];
    int      _pinLen = 0;
    uint32_t _pinPopAt = 0;
    int      _pinCursor = 0;
    float    _pinWheel = 0;

    int   _sel = 0;
    float _selAnim = 0;
    float _scrollAnim = 0;
    int   _actionSlot = -1;
    char  _fingerprints[MAX_KEYS][52];

    enum ConfirmAction { CONFIRM_DELETE_KEY, CONFIRM_DELETE_PASSKEY, CONFIRM_RESET_PASSKEYS, CONFIRM_FACTORY_RESET };
    ConfirmAction _confirmAction = CONFIRM_DELETE_KEY;
    int      _confirmChoice = 0;
    UiState  _confirmReturn = ST_KEYS;
    const Passkey *_confirmPasskey = nullptr;

    enum WorkAction { WORK_UNLOCK, WORK_SET_PIN, WORK_CHANGE_PIN, WORK_DELETE_KEY, WORK_DELETE_PASSKEY,
                      WORK_RESET_PASSKEYS, WORK_FACTORY_RESET };
    WorkAction _work = WORK_UNLOCK;

    char  _name[KEY_NAME_MAX_LEN + 1];
    int   _nameLen = 0;
    int   _charCursor = 0;
    float _charWheel = 0;

    MsgKind  _msgKind = MSG_OK;
    char     _msgTitle[32];
    char     _msgSub[48];
    uint32_t _msgDuration = 0;
    UiState  _msgNext = ST_LOCKED;

    SignPrompt   _prompt;
    int          _signAccount = 0;
    uint32_t     _signDeadline = 0;
    uint32_t     _signArmedAt = 0;
    int          _signChoice = 0;
    UiState      _signReturn = ST_KEYS;
    SignDecision _signDecision = SIGN_NONE;

    char     _unlockReason[48];
    bool     _unlockDeclined = false;

    void go(UiState s);
    void showMessage(MsgKind kind, const char *title, const char *sub, UiState next, uint32_t ms = 1400);
    void startWork(WorkAction action);
    void runWork();
    void finishGenerating();
    void randomizePinCursor();
    void openConfirm(ConfirmAction action, UiState back);
    void startPin(PinMode mode);
    int  pinMinLen() const;
    bool animating() const;
    bool isUnlockedState(UiState s) const;
    void computeFingerprints();
    void clearPinBuffers();
    void resetListSelection(int sel = 0);

    void onLocked(ButtonEvent e);
    void onPin(ButtonEvent e);
    void onKeys(ButtonEvent e);
    void onKeyActions(ButtonEvent e);
    void onConfirm(ButtonEvent e);
    void onName(ButtonEvent e);
    void onSign(ButtonEvent e);
    int  signOptionCount() const;
    const char *signOptionLabel(int idx, char *buf, size_t bufLen) const;
    void onSettings(ButtonEvent e);
    void onPasskeys(ButtonEvent e);
    void submitPin();

    void render(uint32_t now);
    void drawBoot(uint32_t now);
    void drawLocked(uint32_t now);
    void drawPin(uint32_t now);
    void drawVerifying(uint32_t now, const char *title, const char *sub);
    void drawMessage(uint32_t now);
    void drawKeys(uint32_t now);
    void drawKeyActions(uint32_t now);
    void drawFingerprint(uint32_t now);
    void drawConfirm(uint32_t now);
    void drawName(uint32_t now);
    void drawSign(uint32_t now);
    void drawSettings(uint32_t now);
    void drawPasskeys(uint32_t now);
    void drawAbout(uint32_t now);
    void drawBackupNotice(uint32_t now);

    void drawHeader(const char *title, uint16_t accent, const char *chip);
    void drawHints(const char *left, const char *both, const char *right, const char *hold);
    void drawWheel(const char *const *items, int count, float pos, int cursor, int cy, bool okEnabled);
    void drawList(const char *const *labels, const char *const *subs, const uint16_t *colors,
                  int count, int activeIdx, int top, int rowH, int visible);
};

extern UserInterface UI;
