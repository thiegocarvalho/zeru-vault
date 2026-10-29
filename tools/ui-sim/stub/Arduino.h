#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "Print.h"
class __FlashStringHelper;
class String {
public:
    String(const char *s = "") : _s(s) {}
    const char *c_str() const { return _s; }
    unsigned length() const { return strlen(_s); }
private:
    const char *_s;
};
inline size_t Print::print(const String &s) { return write(s.c_str()); }
#define PROGMEM
#define pgm_read_byte(a) (*(const uint8_t *)(a))
#define pgm_read_word(a) (*(const uint16_t *)(a))
#define pgm_read_dword(a) (*(const uint32_t *)(a))
#define pgm_read_pointer(a) (*(void *const *)(a))
#ifndef PI
#define PI 3.1415926535897932384626433832795
#endif
#define HIGH 1
#define LOW 0
#define OUTPUT 1
#define INPUT 0
#define INPUT_PULLUP 2
typedef uint8_t byte;
typedef bool boolean;
extern uint32_t g_now;
extern int g_pin[64];
inline uint32_t millis() { return g_now; }
inline void delay(uint32_t) {}
inline void yield() {}
inline void pinMode(int, int) {}
inline void digitalWrite(int, int) {}
inline int digitalRead(int p) { return g_pin[p]; }
