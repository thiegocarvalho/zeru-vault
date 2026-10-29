#pragma once
#include <Arduino.h>

enum ButtonEvent {
    BTN_NONE = 0,
    BTN_LEFT_CLICK,
    BTN_RIGHT_CLICK,
    BTN_BOTH_CLICK,
    BTN_BOTH_HOLD
};

class ButtonManager {
public:
    static constexpr uint32_t DEBOUNCE_MS  = 25;
    static constexpr uint32_t BOTH_HOLD_MS = 800;

    void begin();
    ButtonEvent update();
    uint8_t holdProgress() const;
    void setHoldMs(uint32_t ms) { _holdMs = ms; }
    void setRepeat(bool enabled) { _repeatEnabled = enabled; }
    void suppressUntilRelease() { _suppress = true; }
    uint32_t gestureStart() const { return _gestureStart; }

private:
    struct Debounced {
        bool stable = false;
        bool lastRaw = false;
        uint32_t changedAt = 0;
    };
    Debounced _l, _r;

    bool _gestureActive = false;
    bool _sawLeft = false, _sawRight = false, _sawBoth = false;
    bool _holdFired = false;
    bool _suppress = false;
    bool _repeatEnabled = true;
    uint32_t _holdMs = BOTH_HOLD_MS;
    uint32_t _bothSince = 0;

    static constexpr uint32_t REPEAT_DELAY_MS = 450;
    static constexpr uint32_t REPEAT_RATE_MS  = 110;
    bool _repeating = false;
    uint32_t _gestureStart = 0;
    uint32_t _lastRepeat = 0;

    static bool debounce(Debounced &d, bool raw, uint32_t now);
};
