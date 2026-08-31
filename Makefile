# Hiraishin WorkMask PICO -- Makefile
#
# Produces a Crystal Palace PICO with per-function encrypt-at-rest.
#
# Targets:
#   all      - compile + encrypt (ready for Crystal Palace link)
#   compile  - compile C sources to COFF object files
#   encrypt  - post-link encrypt function bodies + patch metadata
#   pico     - link PICO blob with Crystal Palace (requires CP_JAR)
#   clean    - remove build artifacts

SHELL   := /bin/bash
export TMPDIR := /tmp

CC      ?= x86_64-w64-mingw32-gcc
CP_JAR  ?= crystalpalace.jar
PYTHON  ?= python3
BINDIR  := bin

CFLAGS := -DWIN_X64 -c -masm=intel -Wall -Wno-pointer-arith \
          -Wno-int-to-pointer-cast \
          -fno-toplevel-reorder -fno-jump-tables -fno-exceptions \
          -fno-stack-protector -fno-asynchronous-unwind-tables \
          -Iinclude -O1

.PHONY: all compile encrypt pico clean

all: encrypt

$(BINDIR):
	mkdir -p $(BINDIR)

# ─── Compile ─────────────────────────────────────────────────────────

compile: $(BINDIR)/workmask.x64.o $(BINDIR)/protected_funcs.x64.o

$(BINDIR)/workmask.x64.o: src/workmask.c include/workmask.h include/helpers.h include/workmask_dfr.h | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BINDIR)/protected_funcs.x64.o: src/protected_funcs.c src/protected_funcs.h include/workmask.h | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

# ─── Encrypt (patches metadata + XOR-encrypts function bodies) ──────

encrypt: $(BINDIR)/protected_funcs.enc.x64.o

$(BINDIR)/protected_funcs.enc.x64.o: compile
	$(PYTHON) tools/hir_encrypt.py \
		--obj $(BINDIR)/protected_funcs.x64.o \
		--output $@

# ─── Crystal Palace link (requires crystalpalace.jar) ────────────────

pico: encrypt $(BINDIR)/workmask.x64.o
	java -jar $(CP_JAR) buildPic ./hiraishin.spec x64 $(BINDIR)/hiraishin.pico.bin

# ─── Clean ───────────────────────────────────────────────────────────

clean:
	rm -rf $(BINDIR)
