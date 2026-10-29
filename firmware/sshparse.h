#pragma once
#include <Arduino.h>

bool sshParseUserauth(const uint8_t *data, size_t len,
                      const uint8_t expectedPub[32],
                      char *user, size_t userMax,
                      char *hostFp, size_t hostFpMax);
