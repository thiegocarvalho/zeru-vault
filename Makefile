FQBN ?= esp32:esp32:lilygo_t_display_s3:CDCOnBoot=cdc,USBMode=default
FLASH_PORT ?= /dev/ttyACM0
FIRMWARE_DIR := firmware
AGENT := python3 -I ./agent/ssh_vault_agent.py
BUILD_FLAGS := --build-property "build.defines=-DBOARD_HAS_PSRAM"
OUT := build
ESPTOOL ?= $(lastword $(sort $(wildcard $(HOME)/.arduino15/packages/esp32/tools/esptool_py/5.*/esptool)))
GFX_LIB ?= $(HOME)/Arduino/libraries/GFX_Library_for_Arduino/src
BOOT_APP0 ?= $(firstword $(wildcard $(HOME)/.arduino15/packages/esp32/hardware/esp32/*/tools/partitions/boot_app0.bin))

.PHONY: all build flash install-service uninstall-service install-udev status pubkey test screenshots clean

all: build

build:
	arduino-cli compile --fqbn $(FQBN) $(BUILD_FLAGS) --warnings all --output-dir $(OUT) $(FIRMWARE_DIR)

flash: build
	@echo ">>> Firmware updates need physical presence (USB auto-reset is disabled)."
	@echo ">>> Hold BOOT (GPIO 0, the button labelled Down on screen), tap RST, release BOOT, then press Enter."
	@read _
	-systemctl --user stop zeru-vault.service 2>/dev/null || true
	@test -n "$(ESPTOOL)" || { echo "esptool not found: install the esp32:esp32 core with arduino-cli"; exit 1; }
	$(ESPTOOL) --chip esp32s3 -p $(FLASH_PORT) --before no-reset --after no-reset \
		read-flash 0x9000 0x5000 $(OUT)/nvs-backup-$$(date +%Y%m%d-%H%M%S).bin
	$(ESPTOOL) --chip esp32s3 -p $(FLASH_PORT) -b 921600 --before no-reset --after no-reset write-flash -z \
		0x0 $(OUT)/firmware.ino.bootloader.bin \
		0x8000 $(OUT)/firmware.ino.partitions.bin \
		0xe000 $(BOOT_APP0) \
		0x10000 $(OUT)/firmware.ino.bin
	@echo ">>> Done (NVS untouched, backup saved in $(OUT)/). Tap RST to start the new firmware."
	-systemctl --user start zeru-vault.service 2>/dev/null || true

install-service:
	$(AGENT) install-service

uninstall-service:
	$(AGENT) uninstall-service

install-udev:
	sudo install -m 0644 udev/70-zeru-vault.rules /etc/udev/rules.d/70-zeru-vault.rules
	sudo udevadm control --reload-rules
	sudo udevadm trigger --subsystem-match=tty --subsystem-match=hidraw

status:
	$(AGENT) status

pubkey:
	$(AGENT) pubkey

test:
	$(AGENT) test

screenshots:
	mkdir -p $(OUT)/ui-sim
	g++ -std=gnu++17 -O1 -w -Itools/ui-sim/stub -I$(FIRMWARE_DIR) -I$(GFX_LIB) -o $(OUT)/ui-sim/ui-sim \
		tools/ui-sim/main.cpp tools/ui-sim/fake_vault.cpp $(FIRMWARE_DIR)/ui.cpp $(FIRMWARE_DIR)/buttons.cpp \
		$(GFX_LIB)/Arduino_GFX.cpp $(GFX_LIB)/Arduino_G.cpp $(GFX_LIB)/canvas/Arduino_Canvas.cpp $(GFX_LIB)/Arduino_DataBus.cpp
	$(OUT)/ui-sim/ui-sim $(OUT)/ui-sim > /dev/null
	python3 -I tools/ui-sim/topng.py $(OUT)/ui-sim docs/images

clean:
	rm -rf build dist $(FIRMWARE_DIR)/build agent/__pycache__
