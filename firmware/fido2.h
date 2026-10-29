#pragma once
#include <Arduino.h>
#include "vault.h"
#include "ui.h"

class Fido2Authenticator {
public:
    static constexpr uint32_t UNLOCK_WAIT_MS = 60000;

    void begin();
    void update();
    bool pending() const { return _waitState != WAIT_NONE; }

private:
    enum WaitState { WAIT_NONE = 0, WAIT_UNLOCK, WAIT_MAKE_CRED, WAIT_GET_ASSERT, WAIT_RESET };
    WaitState _waitState = WAIT_NONE;
    uint32_t  _waitCid = 0;
    int       _waitSlot = -1;
    uint32_t  _lastKeepalive = 0;
    uint32_t  _waitDeadline = 0;

    uint8_t _reqCmd = 0;
    size_t  _reqLen = 0;
    uint8_t _reqBuf[1024];

    char    _rpId[RP_ID_MAX_LEN + 1];
    uint8_t _rpIdHash[32];
    uint8_t _clientDataHash[32];
    uint8_t _userId[USER_ID_MAX_LEN];
    uint8_t _userIdLen = 0;
    char    _userName[USER_NAME_MAX_LEN + 1];
    int8_t  _credAlg = -7;
    bool    _excludeMatched = false;
    bool    _makeResident = false;
    bool    _uvRequested = false;

    uint8_t        _allowNonce[32];
    const Passkey *_candidates[PROMPT_MAX_ACCOUNTS];
    int            _candidateCount = 0;
    bool           _fromAllowList = false;

    uint32_t _rxCid = 0;
    uint8_t  _rxCmd = 0;
    uint16_t _rxExpected = 0;
    uint16_t _rxOffset = 0;
    uint8_t  _rxSeq = 0;
    uint32_t _rxDeadline = 0;
    uint8_t  _rxBuf[1024];

    void onPacket(const uint8_t pkt[64]);
    void handleMessage(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len);
    void handleCbor(uint32_t cid, const uint8_t *data, size_t len);
    void dispatchCtap(uint32_t cid, uint8_t ctapCmd, const uint8_t *body, size_t len);
    void handleGetInfo(uint32_t cid);
    void handleMakeCredential(uint32_t cid, const uint8_t *cbor, size_t len);
    void handleGetAssertion(uint32_t cid, const uint8_t *cbor, size_t len);
    void handleReset(uint32_t cid);
    void hintOtherSlots(const uint8_t *allowList, size_t allowLen);

    void finishMakeCredential();
    void finishGetAssertion(int account, bool userPresent);
    void endWait(uint8_t status);

    void sendResponse(uint32_t cid, uint8_t cmd, const uint8_t *data, size_t len);
    void sendCborStatus(uint32_t cid, uint8_t status);
    void sendError(uint32_t cid, uint8_t err);
    void sendKeepalive(uint32_t cid, uint8_t status);
};

extern Fido2Authenticator Fido2;
