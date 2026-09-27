CC ?= gcc
GO ?= go
CFLAGS ?= -std=c11 -Wall -Wextra -Werror
BUILD_DIR ?= /var/lib/oncache/build/FNCache/tests
TARGET := $(BUILD_DIR)/abi-layout
BEHAVIOR_TARGET := $(BUILD_DIR)/bpf-behavior
RUN ?= sudo -n
INCLUDES := -I../bpf/include
BPF_DIR := ../bpf
NORMAL_OBJ := $(BUILD_DIR)/bpf-normal/tc_prog_kern.o
ADJUST_OBJ := $(BUILD_DIR)/bpf-fail-adjust/tc_prog_kern.o
STORE_OBJ := $(BUILD_DIR)/bpf-fail-store/tc_prog_kern.o
REDIRECT_OBJ := $(BUILD_DIR)/bpf-fail-redirect/tc_prog_kern.o
INTEGRATION_BUILD_DIR ?= $(BUILD_DIR)/m2-integration
INTEGRATION_BPF_OBJ := $(INTEGRATION_BUILD_DIR)/bpf/tc_prog_kern.o

.PHONY: all test test-bpf test-m2-integration clean

all: $(TARGET)

$(TARGET): abi_layout.c ../bpf/include/oncache_abi.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(INCLUDES) -o "$@" "$<"

test: $(TARGET)
	"$(TARGET)"

$(NORMAL_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(BUILD_DIR)/bpf-normal"

$(ADJUST_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(BUILD_DIR)/bpf-fail-adjust" CFLAGS="-DONCACHE_TEST_FAIL_ADJUST_ROOM"

$(STORE_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(BUILD_DIR)/bpf-fail-store" CFLAGS="-DONCACHE_TEST_FAIL_STORE_BYTES"

$(REDIRECT_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(BUILD_DIR)/bpf-fail-redirect" CFLAGS="-DONCACHE_TEST_FAIL_REDIRECT"

$(BEHAVIOR_TARGET): bpf_behavior_test.c ../bpf/include/oncache_abi.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(INCLUDES) -o "$@" "$<" $$(pkg-config --libs libbpf) -lpthread

test-bpf: $(BEHAVIOR_TARGET) $(NORMAL_OBJ) $(ADJUST_OBJ) $(STORE_OBJ) $(REDIRECT_OBJ)
	$(RUN) "$(BEHAVIOR_TARGET)" "$(NORMAL_OBJ)" "$(ADJUST_OBJ)" "$(STORE_OBJ)" "$(REDIRECT_OBJ)"

$(INTEGRATION_BPF_OBJ):
	$(MAKE) -C "$(BPF_DIR)" BUILD_DIR="$(INTEGRATION_BUILD_DIR)/bpf"

test-m2-integration: $(INTEGRATION_BPF_OBJ)
	$(RUN) env ONCACHE_M2_INTEGRATION=1 ONCACHE_BPF_ELF="$(abspath $(INTEGRATION_BPF_OBJ))" "$(GO)" test -tags=integration -count=1 ../tests/integration

clean:
	rm -f "$(TARGET)" "$(BEHAVIOR_TARGET)"
