.PHONY: install lint test build-rust clean

install:
	pip install -e .

lint:
	ruff check hot_omelet

test:
	pytest

build-rust:
	@for t in hot_beam_rs hot_bf_rs; do \
		if [ -d "tools/rust/$$t" ]; then \
			echo "== building $$t =="; \
			(cd "tools/rust/$$t" && cargo build --release) || echo "warn: $$t build failed"; \
		fi \
	done

# ── Android emulator (optional; requires ANDROID_SDK_ROOT or adb/emulator on PATH) ──

ANDROID_SDK_ROOT ?= $(HOME)/android-sdk
ADB := $(shell command -v adb 2>/dev/null || echo $(ANDROID_SDK_ROOT)/platform-tools/adb)
EMULATOR := $(shell command -v emulator 2>/dev/null || echo $(ANDROID_SDK_ROOT)/emulator/emulator)
AVD_NAME ?= pentest

.PHONY: emu-start emu-stop emu-shell emu-status

emu-start:
	$(EMULATOR) -avd $(AVD_NAME) -gpu host -no-audio -writable-system

emu-stop:
	-$(ADB) emu kill 2>/dev/null || true

emu-shell:
	$(ADB) shell

emu-status:
	@$(ADB) devices

# ── Frida (optional; requires frida-tools + a rooted device/emulator) ──

FRIDA_SERVER_DIR ?= /data/local/tmp

.PHONY: frida-server-push frida-server-start frida-ps

frida-server-push:
	$(ADB) push $(FRIDA_SERVER_LOCAL) $(FRIDA_SERVER_DIR)/frida-server
	$(ADB) shell chmod 755 $(FRIDA_SERVER_DIR)/frida-server

frida-server-start:
	$(ADB) root || true
	$(ADB) shell "$(FRIDA_SERVER_DIR)/frida-server -D &"

frida-ps:
	frida-ps -U

frida-attach:
	@echo "Usage: make frida-attach APP=com.example.app SCRIPT=path/to/script.js"
	@test -n "$(APP)" && test -n "$(SCRIPT)" && frida -U -f $(APP) -l $(SCRIPT) --no-pause || true

clean:
	rm -rf build dist *.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
