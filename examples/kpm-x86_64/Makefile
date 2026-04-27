# SPDX-License-Identifier: GPL-2.0-or-later
CLANG ?= clang
OBJCOPY ?= llvm-objcopy

KPM_CFLAGS := \
	-target x86_64-linux-gnu \
	-ffreestanding \
	-fno-builtin \
	-fno-stack-protector \
	-fno-pic \
	-fno-plt \
	-fno-common \
	-mcmodel=kernel \
	-mno-red-zone \
	-mno-sse \
	-mno-mmx \
	-fno-asynchronous-unwind-tables \
	-fno-unwind-tables \
	-fno-exceptions \
	-fno-jump-tables \
	-fcf-protection=none \
	-Wall \
	-Wextra \
	-Werror \
	-Iinclude

EXAMPLES := hello_kpm_x86_64 control_kpm inline_hook fp_hook hotpatch failure_cases
OUT := out
KPM_FILES := $(addprefix $(OUT)/,$(addsuffix .kpm,$(EXAMPLES)))

.PHONY: all clean inspect
all: $(KPM_FILES)

$(OUT):
	mkdir -p $@

$(OUT)/%.o: %/main.c include/kpm_x86_64.h | $(OUT)
	$(CLANG) $(KPM_CFLAGS) -c $< -o $@

$(OUT)/%.kpm: $(OUT)/%.o
	cp $< $@

inspect: all
	@for file in $(KPM_FILES); do \
		echo "$$file"; \
		readelf -h "$$file" | grep 'Type:\\|Machine:'; \
		readelf -S "$$file" | grep '.kpm.'; \
	done

clean:
	rm -rf $(OUT)
