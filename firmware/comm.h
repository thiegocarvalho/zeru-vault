#pragma once
#include <Arduino.h>

class HostComm {
public:
    static constexpr size_t CHALLENGE_MAX = 1024;
    static constexpr size_t RX_MAX = 16 + 8 + CHALLENGE_MAX * 2;
    static constexpr uint32_t UNLOCK_WAIT_MS = 60000;

    void begin();
    void update();
    bool signPending() const { return _state != IDLE; }

private:
    enum State { IDLE = 0, WAIT_UNLOCK, WAIT_CONFIRM };

    char   _rx[RX_MAX + 1];
    size_t _rxLen = 0;
    bool   _overflow = false;

    State    _state = IDLE;
    uint32_t _waitDeadline = 0;
    char     _pendingId[17];
    int      _pendingSlot = -1;
    uint8_t  _challenge[CHALLENGE_MAX];
    size_t   _challengeLen = 0;

    void processLine(char *line);
    void handleSign(const char *id, const char *hex);
    void beginConfirm();
    void finishPending(const char *reply);
    void reply(const char *id, const char *fmt, ...);
};

extern HostComm Comm;
