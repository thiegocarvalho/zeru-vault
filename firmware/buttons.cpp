#include "buttons.h"
#include "pin_config.h"

void ButtonManager::begin() {
    pinMode(PIN_BTN_LEFT, INPUT_PULLUP);
    pinMode(PIN_BTN_RIGHT, INPUT_PULLUP);
}

bool ButtonManager::debounce(Debounced &d, bool raw, uint32_t now) {
    if (raw != d.lastRaw) {
        d.lastRaw = raw;
        d.changedAt = now;
    } else if (raw != d.stable && (now - d.changedAt) >= DEBOUNCE_MS) {
        d.stable = raw;
    }
    return d.stable;
}

uint8_t ButtonManager::holdProgress() const {
    if (!(_l.stable && _r.stable) || _holdFired || _suppress || !_sawBoth) return 0;
    uint32_t held = millis() - _bothSince;
    if (held >= _holdMs) return 255;
    return (uint8_t)((held * 255) / _holdMs);
}

ButtonEvent ButtonManager::update() {
    uint32_t now = millis();
    bool left  = debounce(_l, digitalRead(PIN_BTN_LEFT)  == LOW, now);
    bool right = debounce(_r, digitalRead(PIN_BTN_RIGHT) == LOW, now);

    if (_suppress) {
        if (left || right) return BTN_NONE;
        _suppress = false;
        _gestureActive = false;
        return BTN_NONE;
    }

    if (left || right) {
        if (!_gestureActive) {
            _gestureActive = true;
            _sawLeft = _sawRight = _sawBoth = _holdFired = _repeating = false;
            _gestureStart = now;
        }

        if (_repeating) {
            if ((left != right) && (now - _lastRepeat) >= REPEAT_RATE_MS) {
                _lastRepeat = now;
                return left ? BTN_LEFT_CLICK : BTN_RIGHT_CLICK;
            }
            return BTN_NONE;
        }

        _sawLeft  |= left;
        _sawRight |= right;

        if (_repeatEnabled && (left != right) && !_sawBoth && !(_sawLeft && _sawRight) &&
            (now - _gestureStart) >= REPEAT_DELAY_MS) {
            _repeating = true;
            _lastRepeat = now;
            return left ? BTN_LEFT_CLICK : BTN_RIGHT_CLICK;
        }

        if (left && right) {
            if (!_sawBoth) {
                _sawBoth = true;
                _bothSince = now;
            } else if (!_holdFired && (now - _bothSince) >= _holdMs) {
                _holdFired = true;
                return BTN_BOTH_HOLD;
            }
        }
        return BTN_NONE;
    }

    if (_gestureActive) {
        _gestureActive = false;
        if (_holdFired || _repeating) return BTN_NONE;
        if (_sawBoth || (_sawLeft && _sawRight)) return BTN_BOTH_CLICK;
        if (_sawLeft)  return BTN_LEFT_CLICK;
        if (_sawRight) return BTN_RIGHT_CLICK;
    }
    return BTN_NONE;
}
