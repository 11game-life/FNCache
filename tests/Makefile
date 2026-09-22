CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror
BUILD_DIR ?= /var/lib/oncache/build/FNCache/tests
TARGET := $(BUILD_DIR)/abi-layout
INCLUDES := -I../bpf/include

.PHONY: all test clean

all: $(TARGET)

$(TARGET): abi_layout.c ../bpf/include/oncache_abi.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(INCLUDES) -o "$@" "$<"

test: $(TARGET)
	"$(TARGET)"

clean:
	rm -f "$(TARGET)"
