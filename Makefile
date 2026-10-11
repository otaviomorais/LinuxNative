CC = aarch64-linux-gnu-gcc
PYTHON ?= python3
RUNNER ?= qemu-aarch64
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -fno-strict-aliasing
LDFLAGS ?= -static
BUILD := build
GUEST_FLAGS := -O2 -std=c11 -Wall -Wextra -Werror -ffreestanding -fno-builtin \
	-fno-stack-protector -fno-pie -fno-unwind-tables -fno-asynchronous-unwind-tables \
	-nostdlib -static -no-pie -Wl,--build-id=none -Wl,-T,tests/probe.ld
ifneq ($(findstring clang,$(CC)),)
GUEST_FLAGS += -Wno-unused-command-line-argument
endif
PROBE_FLAGS := -nostdlib -static -no-pie -Wl,--build-id=none -Wl,-T,tests/probe.ld
ifneq ($(findstring clang,$(CC)),)
PROBE_FLAGS += -Wno-unused-command-line-argument
endif
PIE_FLAGS := -O2 -std=c11 -Wall -Wextra -Werror -ffreestanding -fno-builtin \
	-fno-stack-protector -fPIE -fno-unwind-tables -fno-asynchronous-unwind-tables \
	-nostdlib -static -Wl,-pie -Wl,--build-id=none -Wl,-T,tests/pie.ld
ifneq ($(findstring clang,$(CC)),)
PIE_FLAGS += -Wno-unused-command-line-argument
endif

.PHONY: all test clean
all: $(BUILD)/lnative $(BUILD)/probe $(BUILD)/file-scan $(BUILD)/file-abi $(BUILD)/mem-abi $(BUILD)/mini-ls $(BUILD)/fs-mut $(BUILD)/pie-abi

$(BUILD):
	mkdir -p $@

$(BUILD)/lnative: src/main.c src/elf.c src/runtime.c src/gateway.S src/lnative.h include/linux_aarch64.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c src/elf.c src/runtime.c src/gateway.S $(LDFLAGS) -o $@

$(BUILD)/probe: tests/probe.S tests/probe.ld | $(BUILD)
	$(CC) $(PROBE_FLAGS) tests/probe.S -o $@

$(BUILD)/file-scan: examples/file-scan.c examples/start.S examples/guest.h include/linux_aarch64.h tests/probe.ld | $(BUILD)
	$(CC) $(GUEST_FLAGS) examples/start.S examples/file-scan.c -o $@

$(BUILD)/file-abi: tests/file-abi.c examples/start.S examples/guest.h include/linux_aarch64.h tests/probe.ld | $(BUILD)
	$(CC) $(GUEST_FLAGS) examples/start.S tests/file-abi.c -o $@

$(BUILD)/mem-abi: tests/mem-abi.c examples/start.S examples/guest.h include/linux_aarch64.h tests/probe.ld | $(BUILD)
	$(CC) $(GUEST_FLAGS) examples/start.S tests/mem-abi.c -o $@

$(BUILD)/mini-ls: examples/mini-ls.c examples/start.S examples/micro-libc.h examples/guest.h include/linux_aarch64.h tests/probe.ld | $(BUILD)
	$(CC) $(GUEST_FLAGS) examples/start.S examples/mini-ls.c -o $@

$(BUILD)/fs-mut: tests/fs-mut.c examples/start.S examples/micro-libc.h examples/guest.h include/linux_aarch64.h tests/probe.ld | $(BUILD)
	$(CC) $(GUEST_FLAGS) examples/start.S tests/fs-mut.c -o $@

$(BUILD)/pie-abi: tests/pie-abi.c examples/start.S examples/micro-libc.h examples/guest.h include/linux_aarch64.h tests/pie.ld | $(BUILD)
	$(CC) $(PIE_FLAGS) examples/start.S tests/pie-abi.c -o $@

test: all
	$(PYTHON) tests/test_runtime.py --runner '$(RUNNER)'

clean:
	rm -rf $(BUILD)
