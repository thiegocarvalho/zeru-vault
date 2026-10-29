#pragma once
#include "Arduino_GFX.h"
#include "canvas/Arduino_Canvas.h"
extern uint16_t g_frame[320 * 170];
class Arduino_ESP32LCD8 : public Arduino_DataBus {
public:
    Arduino_ESP32LCD8(int, int, int, int, int, int, int, int, int, int, int, int) {}
    bool begin(int32_t, int8_t) override { return true; }
    void beginWrite() override {}
    void endWrite() override {}
    void writeCommand(uint8_t) override {}
    void writeCommand16(uint16_t) override {}
    void writeCommandBytes(uint8_t *, uint32_t) override {}
    void write(uint8_t) override {}
    void write16(uint16_t) override {}
    void writeRepeat(uint16_t, uint32_t) override {}
    void writeBytes(uint8_t *, uint32_t) override {}
    void writePixels(uint16_t *, uint32_t) override {}
};
class Arduino_ST7789 : public Arduino_Canvas {
public:
    Arduino_ST7789(Arduino_DataBus *, int, int, bool, int w, int h, int, int, int, int) : Arduino_Canvas(w, h, nullptr) {}
    void draw16bitRGBBitmap(int16_t, int16_t, uint16_t *b, int16_t w, int16_t h) override { memcpy(g_frame, b, (size_t)w * h * 2); }
};
