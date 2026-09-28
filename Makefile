# GGnetPatch - build
#
# Produces:
#   build/ggpatch.exe    64-bit loader/controller
#   build/gghook32.dll   32-bit hook (injected into launcher.exe)
#   build/gghook64.dll   64-bit hook (injected into GGnet.exe)
#
# Requires mingw-w64 (i686 + x86_64) on PATH. The host `test` target runs the
# disassembler unit test with the native compiler.

CC32    := i686-w64-mingw32-gcc
CC64    := x86_64-w64-mingw32-gcc
HOSTCC  := cc

CFLAGS  := -O2 -Wall -Wextra -D_WIN32_WINNT=0x0601 -DUNICODE -D_UNICODE
INCS    := -Isrc
BUILD   := build

DLL_SRC := src/gghook.c src/hook.c src/lde.c

.PHONY: all clean test dist

all: $(BUILD)/ggpatch.exe $(BUILD)/gghook32.dll $(BUILD)/gghook64.dll

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/gghook32.dll: $(DLL_SRC) src/ggpatch.h src/lde.h | $(BUILD)
	$(CC32) $(CFLAGS) $(INCS) -shared -static -o $@ $(DLL_SRC)

$(BUILD)/gghook64.dll: $(DLL_SRC) src/ggpatch.h src/lde.h | $(BUILD)
	$(CC64) $(CFLAGS) $(INCS) -shared -static -o $@ $(DLL_SRC)

$(BUILD)/ggpatch.exe: src/ggpatch.c src/ggpatch.h | $(BUILD)
	$(CC64) $(CFLAGS) $(INCS) -static -o $@ src/ggpatch.c

test:
	$(HOSTCC) -Wall -Wextra -O2 -Isrc src/lde.c tests/lde_test.c -o /tmp/gp_lde_test
	/tmp/gp_lde_test

dist: all
	rm -rf dist && mkdir -p dist/ggpatch
	cp $(BUILD)/ggpatch.exe dist/ggpatch/
	cp $(BUILD)/gghook32.dll dist/ggpatch/
	cp $(BUILD)/gghook64.dll dist/ggpatch/
	cp README.md dist/ggpatch/
	cp proxmox-hardening.md dist/ggpatch/

clean:
	rm -rf $(BUILD) dist
