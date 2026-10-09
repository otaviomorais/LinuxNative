CC = aarch64-linux-gnu-gcc
PYTHON ?= python3
RUNNER ?= qemu-aarch64
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -fno-strict-aliasing
LDFLAGS ?= -static
BUILD := build

.PHONY: all test clean
all: $(BUILD)/lnative $(BUILD)/probe

$(BUILD):
	mkdir -p $@

$(BUILD)/lnative: src/main.c src/elf.c src/runtime.c src/gateway.S src/lnative.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c src/elf.c src/runtime.c src/gateway.S $(LDFLAGS) -o $@

$(BUILD)/probe: tests/probe.S tests/probe.ld | $(BUILD)
	$(CC) -nostdlib -static -no-pie -Wl,--build-id=none -Wl,-T,tests/probe.ld tests/probe.S -o $@

test: all
	$(PYTHON) tests/test_runtime.py --runner '$(RUNNER)'

clean:
	rm -rf $(BUILD)
