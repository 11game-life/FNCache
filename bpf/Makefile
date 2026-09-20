CLANG ?= /usr/lib/llvm-18/bin/clang
LLC ?= /usr/lib/llvm-18/bin/llc
BUILD_DIR ?= /var/lib/oncache/build/FNCache/bpf
MULTIARCH_INCLUDE ?= /usr/include/x86_64-linux-gnu

BPF_SRC := tc_prog_kern.c
BPF_LL := $(BUILD_DIR)/tc_prog_kern.ll
BPF_OBJ := $(BUILD_DIR)/tc_prog_kern.o
BPF_HEADERS := $(wildcard include/*.h)
INCLUDES := -I$(CURDIR)/include

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_LL): $(BPF_SRC) $(BPF_HEADERS)
	@mkdir -p "$(BUILD_DIR)"
	"$(CLANG)" -S -target bpf -D__BPF_TRACING__ $(CFLAGS) \
		-Wall -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types -Wno-unused-but-set-variable \
		-Werror -O2 -emit-llvm -c -g \
		$(INCLUDES) -I$(MULTIARCH_INCLUDE) -o "$@" "$<"

$(BPF_OBJ): $(BPF_LL)
	"$(LLC)" -march=bpf -filetype=obj -o "$@" "$<"

clean:
	rm -f "$(BPF_LL)" "$(BPF_OBJ)"
