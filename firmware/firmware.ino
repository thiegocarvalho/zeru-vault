#include <Arduino.h>
#include "pin_config.h"
#include "buttons.h"
#include "vault.h"
#include "ui.h"
#include "comm.h"
#include "fido2.h"

static ButtonManager buttons;

void setup() {
    Fido2.begin();
    Comm.begin();
    buttons.begin();
    Vault.begin();
    UI.begin(&buttons);
}

void loop() {
    ButtonEvent evt = buttons.update();
    UI.update(evt);
    Comm.update();
    Fido2.update();

    if (Vault.isUnlocked()) {
        if (Vault.idleMs() >= AUTO_LOCK_IDLE_MS) {
            Vault.lock();
            UI.notifyAutoLocked("No button pressed for 15 min");
        } else if (Vault.sessionMs() >= SESSION_MAX_MS) {
            Vault.lock();
            UI.notifyAutoLocked("12 h session limit reached");
        }
    }

    vTaskDelay(pdMS_TO_TICKS(5));
}
