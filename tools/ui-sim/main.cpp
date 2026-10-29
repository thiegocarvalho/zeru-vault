#include "ui.h"
#include "pin_config.h"
#include <stdio.h>

uint32_t g_now = 0;
int g_pin[64];
uint16_t g_frame[320 * 170];

static ButtonManager btn;
static const char *g_outDir = ".";

static void tick(uint32_t ms) {
    for (uint32_t t = 0; t < ms; t += 5) {
        g_now += 5;
        UI.update(btn.update());
    }
}

static void press(bool up, bool down, uint32_t holdMs = 90) {
    g_pin[PIN_BTN_LEFT] = up ? LOW : HIGH;
    g_pin[PIN_BTN_RIGHT] = down ? LOW : HIGH;
    tick(holdMs);
    g_pin[PIN_BTN_LEFT] = HIGH;
    g_pin[PIN_BTN_RIGHT] = HIGH;
    tick(90);
}

static void up(int n = 1) { while (n--) press(true, false); }
static void down(int n = 1) { while (n--) press(false, true); }
static void both() { press(true, true); }
static void hold() { press(true, true, 900); }

static void shot(const char *name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.ppm", g_outDir, name);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fprintf(f, "P6\n320 170\n255\n");
    for (int i = 0; i < 320 * 170; i++) {
        uint16_t c = g_frame[i];
        uint8_t rgb[3] = {(uint8_t)((c >> 8) & 0xF8), (uint8_t)((c >> 3) & 0xFC), (uint8_t)((c << 3) & 0xF8)};
        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
    printf("%s\n", name);
}

static SignPrompt prompt(PromptKind kind, const char *target, const char *detail) {
    SignPrompt p;
    memset(&p, 0, sizeof(p));
    p.kind = kind;
    strncpy(p.keyName, "PROD_SERVERS", KEY_NAME_MAX_LEN);
    strncpy(p.target, target, RP_ID_MAX_LEN);
    strncpy(p.detail, detail, sizeof(p.detail) - 1);
    return p;
}

static void request(const SignPrompt &p, const char *name, int ups) {
    UI.requestSignConfirmation(p);
    tick(1000);
    up(ups);
    tick(300);
    shot(name);
    hold();
    tick(1500);
}

int main(int argc, char **argv) {
    if (argc > 1) g_outDir = argv[1];
    for (int i = 0; i < 64; i++) g_pin[i] = HIGH;
    UI.begin(&btn);

    tick(1000); shot("boot");
    tick(1200); shot("welcome");
    both(); tick(300);
    for (int i = 0; i < 4; i++) both();
    tick(500); shot("create-pin");
    for (int i = 0; i < 4; i++) both();
    both(); tick(300);
    for (int i = 0; i < 8; i++) both();
    both(); tick(3300); shot("backup-notice");
    both(); tick(400);
    hold(); tick(1600); shot("locked");
    both(); tick(300);
    for (int i = 0; i < 8; i++) both();
    both(); tick(1500); shot("keys");
    both(); tick(500); shot("key-actions");
    down(); both(); tick(500); shot("fingerprint");
    both(); tick(300); hold(); tick(400);
    down(3); both(); tick(500); shot("settings");
    down(); both(); tick(600); shot("passkeys");
    hold(); tick(300); down(3); both(); tick(500); shot("about");
    both(); tick(300); up(1); both(); tick(400); down(); tick(400); shot("factory-reset");
    hold(); tick(300); hold(); tick(400);

    UI.requestSignConfirmation(prompt(PROMPT_SSH_LOGIN, "deploy", "Host SHA256:Zk3tq0pVb8YyX2mQ1aG7c..."));
    tick(200); shot("approve-read-first");
    tick(800); shot("approve-ssh-login");
    up(); tick(300); shot("approve-ssh-login-selected");
    both(); tick(350); shot("approved");
    tick(1500);

    SignPrompt p = prompt(PROMPT_PASSKEY_USE, "github.com", "");
    p.accountCount = 2;
    strcpy(p.accounts[0], "alice");
    strcpy(p.accounts[1], "alice-work");
    request(p, "approve-passkey-accounts", 2);

    p = prompt(PROMPT_PASSKEY_CREATE, "accounts.google.com", "");
    p.accountCount = 1;
    strcpy(p.accounts[0], "alice@gmail.com");
    request(p, "approve-create-passkey", 0);

    request(prompt(PROMPT_SK_USE, "ssh:", "OpenSSH security key login"), "approve-ssh-sk", 0);
    request(prompt(PROMPT_PASSKEY_USE, "very.long.subdomain.chain.example-company.co.uk", ""), "approve-long-domain", 0);
    return 0;
}
