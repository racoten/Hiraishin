# Hiraishin WorkMask

Per-function encrypt-at-rest for Crystal Palace PICOs. Function bodies are XOR-encrypted in the binary and only decrypted in memory when actively executing — re-encrypted the instant they return. Invisible to memory scanners, YARA rules, and static analysis at rest.

Inspired by [MDSec Function Peekaboo](https://www.mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/). Built as a standalone [Crystal Palace](https://www.cobaltstrike.com/product/crystal-palace) PICO — works with Cobalt Strike, Sliver, Adaptix, Mythic, or any PICO-compatible C2.

## Background

### The Problem

Modern EDRs and memory scanners operate on a simple premise: if code exists in executable memory, it can be read and analyzed. During sleep intervals, C2 agents encrypt their entire code section (via techniques like Ekko, Foliage, or Kraken) — but between check-ins, when the agent is actually *running*, every function sits in cleartext. A memory scanner that fires during execution can signature-match any function body, find YARA hits on opcode patterns, or identify known tool fingerprints.

Sleep obfuscation protects the dormant agent. WorkMask protects the *active* agent. Functions are only cleartext for the microseconds they're executing — invisible at every other moment.

### Origin: Function Peekaboo

In October 2025, MDSec published [Function Peekaboo](https://www.mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/) — an LLVM compiler pass that automatically wraps functions with encrypt/decrypt stubs. Functions marked with a `REG_` prefix get their bodies XOR-encrypted in the final binary. The LLVM pass injects `peekaboo_enter()` before each function and `peekaboo_exit()` after the return, toggling `VirtualProtect` and XOR on every call.

The original Peekaboo uses a **single-byte XOR key** (only the low byte of a 32-bit value), which barely shifts entropy. It also targets PE executables with absolute virtual addresses, tying it to a specific binary format.

### Hiraishin: Adapting for Crystal Palace

Hiraishin (雷神, "Thunder God" — named after the Flying Thunder God technique from Naruto, a teleportation seal that appears where you need it and vanishes when you don't) takes the Peekaboo concept and rebuilds it as a **Crystal Palace PICO** — a Position-Independent Code Object that works with any C2 framework.

Key changes from the original Peekaboo:

- **4-byte rolling XOR** instead of single-byte — all 4 key bytes participate, raising encrypted entropy from ~5.0 to ~6.5 bits/byte
- **Position-independent addressing** — relative offsets from code base instead of absolute VAs, so it works at any load address across disparate memory regions
- **Crystal Palace DFR** — API calls resolved via Dynamic Function Resolution (ror13 hashing) at link time, no import table entries
- **Sleep obfuscation integration** — `suspend()` re-encrypts everything before a sleep mask runs, `resume()` clears the flag so functions decrypt on-demand when the agent wakes
- **C2-agnostic** — exports its API via `PicoGetExport()` hash tags; the PICO doesn't know or care what C2 loaded it
- **Manual instrumentation** — uses `WORKMASK_CALL()` macros at call sites instead of requiring an LLVM compiler pass, making it portable to any build pipeline

### How the Technique Works in Detail

The system has three components: **metadata**, **runtime**, and **post-link encryption**.

#### 1. Metadata (HIRMETA_ENTRY)

Each protected function has a 32-byte metadata entry stored in the `.data` section:

```c
typedef struct {
    int32_t   codeOffset;      // signed offset from code base to function body
    uint32_t  funcSize;        // size of the encrypted region in bytes
    uint32_t  xorKey;          // 4-byte rolling XOR key
    uint32_t  prologueSkip;    // bytes to skip at function start
    volatile long refCount;    // atomic reference count
    uint32_t  flags;           // ENABLED, DECRYPTED, SUSPENDED
    uint8_t   reserved[8];     // future use
} HIRMETA_ENTRY;
```

At compile time, `funcSize` is set to `0xDEADBEEF` (a sentinel indicating "not yet patched"). The post-link tool fills in the real values.

#### 2. Post-Link Encryption (hir_encrypt.py)

After compilation, `hir_encrypt.py` processes the COFF object file:

1. Parses the symbol table to find `REG_*` functions and their `g_meta_*` metadata entries
2. Computes function sizes from symbol gaps in the `.text` section
3. Generates random 4-byte XOR keys per function
4. Patches each `HIRMETA_ENTRY` in the `.data` section — writes `codeOffset`, `funcSize`, and `xorKey`
5. XOR-encrypts each function body in the `.text` section
6. Outputs the encrypted `.o` file and a JSON manifest

After this step, the function bodies are encrypted garbage on disk. The metadata tells the runtime where each function lives and how to decrypt it.

#### 3. Runtime (workmask_enter / workmask_exit)

At runtime, the enter/exit cycle works like this:

**Enter (decrypt):**
```
1. Check: is WorkMask suspended? If yes, return (sleep mask is active)
2. Check: is funcSize still the sentinel? If yes, return (metadata not patched)
3. Atomically increment refCount
4. If refCount went from 0 → 1 (first caller):
   a. Compute funcAddr = codeBase + codeOffset + prologueSkip
   b. VirtualProtect(funcAddr, funcSize, PAGE_READWRITE)
   c. XOR the function body with the 4-byte rolling key
   d. VirtualProtect(funcAddr, funcSize, PAGE_EXECUTE_READ)
   e. Set DECRYPTED flag
5. If refCount was already > 0: another thread already decrypted, skip
```

**Exit (re-encrypt):**
```
1. Atomically decrement refCount
2. If refCount reached 0 (last caller):
   a. VirtualProtect → PAGE_READWRITE
   b. XOR again (symmetric — same operation encrypts)
   c. VirtualProtect → PAGE_EXECUTE_READ
   d. Clear DECRYPTED flag
3. If refCount still > 0: other threads still executing, skip
```

The atomic refcounting handles concurrency: if thread A and thread B both call the same function, thread A's enter decrypts it, thread B's enter sees refCount > 0 and skips, both execute, thread B's exit decrements but doesn't re-encrypt (refCount still 1), thread A's exit decrements to 0 and re-encrypts. Recursive calls work the same way.

**Suspend (for sleep obfuscation):**
```
1. Set suspended flag (enter/exit become no-ops)
2. Walk all HIRMETA_ENTRY records
3. For each with DECRYPTED flag set:
   a. Reset refCount to 0
   b. XOR re-encrypt the function body
   c. Clear DECRYPTED flag
```

After suspend, every function body is encrypted. The sleep mask can then safely encrypt the entire code section without double-encrypting already-masked regions.

**Resume:** Simply clears the suspended flag. Functions stay encrypted until the next `workmask_enter()` call — decrypt on demand, minimum exposure time.

## How It Works

```
AT REST          workmask_enter()        EXECUTING        workmask_exit()         AT REST
┌──────────┐    ┌──────────────────┐    ┌──────────┐    ┌──────────────────┐    ┌──────────┐
│ E3 29 4E │───>│ VirtualProtect RW│───>│ 49 89 CA │───>│ VirtualProtect RW│───>│ E3 29 4E │
│ D3 23 71 │    │ XOR decrypt      │    │ 49 89 D1 │    │ XOR encrypt      │    │ D3 23 71 │
│ CC 1F 78 │    │ VirtualProtect RX│    │ 48 85 D2 │    │ VirtualProtect RX│    │ CC 1F 78 │
│ (garbage) │    └──────────────────┘    │ (valid x86)│    └──────────────────┘    │ (garbage) │
└──────────┘                            └──────────┘                            └──────────┘
```

- **Thread-safe**: Atomic refcounting — first caller decrypts, last caller re-encrypts
- **Sleep integration**: `suspend()` re-encrypts all functions before sleep obfuscation, `resume()` clears the flag
- **4-byte rolling XOR**: Per-function random keys, all 4 bytes participate
- **Position-independent**: Relative code offsets, no absolute addresses — works at any load address

## Project Structure

```
include/
  workmask.h          HIRMETA_ENTRY struct, WORKMASK_STATE, WORKMASK_CALL macro
  workmask_dfr.h      Crystal Palace DFR declarations (KERNEL32$VirtualProtect)
  helpers.h           PIC-safe memset/memcpy/strlen, atomic intrinsics (no libc)
  tcg.h               LibTCG API stub (PicoLoad, PicoGetExport, IMPORTFUNCS)
src/
  workmask.c          Runtime: go(), workmask_enter/exit/suspend/resume
  protected_funcs.h   Protected function declarations + metadata externs
  protected_funcs.c   Example REG_* functions with HIRMETA_ENTRY metadata
tools/
  hir_encrypt.py      Post-link tool: patches metadata + encrypts function bodies
hiraishin.spec        Crystal Palace PICO spec file
build.py              Cross-platform build script
Makefile              GNU Make alternative
```

## Quick Start

### Prerequisites

- **MinGW cross-compiler**: `x86_64-w64-mingw32-gcc`
  - Windows (MSYS2): `pacman -S mingw-w64-ucrt-x86_64-gcc`
  - Linux: `apt install gcc-mingw-w64-x86-64`
  - macOS: `brew install mingw-w64`
- **Python 3.6+** (standard library only)

### Build

```bash
python build.py
```

This compiles the COFF objects and encrypts the function bodies:

```
[1/3 workmask.c]        → bin/workmask.x64.o
[2/3 protected_funcs.c] → bin/protected_funcs.x64.o
[3/3 encrypt]           → bin/protected_funcs.enc.x64.o
```

### Build with Crystal Palace

```bash
python build.py --pico --cp-jar /path/to/crystalpalace.jar
```

Produces `bin/hiraishin.pico.bin` — the PICO blob ready for C2 loading.

## Integration

### Writing Protected Functions

Add your functions to `src/protected_funcs.c` with the `REG_` prefix and a metadata entry:

```c
#include "protected_funcs.h"

/* Declare metadata — key is random, funcSize patched by hir_encrypt.py */
DECLARE_WORKMASK_META(my_function, 0xAABBCCDD);

void REG_my_function(void* data, uint32_t size) {
    /* Your sensitive code here — encrypted at rest */
}
```

Declare it in `src/protected_funcs.h`:

```c
void REG_my_function(void* data, uint32_t size);
extern HIRMETA_ENTRY g_meta_my_function;
```

Call it through the WorkMask wrapper:

```c
WORKMASK_CALL(g_meta_my_function, REG_my_function, buffer, bufSize);
```

### Loading from a C2 Agent

```c
/* Load the WorkMask PICO */
IMPORTFUNCS funcs = { LoadLibraryA, GetProcAddress };
char* code = VirtualAlloc(NULL, PicoCodeSize(blob), MEM_COMMIT, PAGE_READWRITE);
char* data = VirtualAlloc(NULL, PicoDataSize(blob), MEM_COMMIT, PAGE_READWRITE);
PicoLoad(&funcs, blob, code, data);
VirtualProtect(code, PicoCodeSize(blob), PAGE_EXECUTE_READ, &old);

/* Initialize */
((void(*)())PicoEntryPoint(blob, code))();

/* Get API by hash tag */
wm_suspend_t suspend = PicoGetExport(code, TAG_WM_SUSPEND);
wm_resume_t  resume  = PicoGetExport(code, TAG_WM_RESUME);

/* In your sleep mask: */
suspend();          /* re-encrypt all before sleep */
do_sleep();         /* Ekko, Foliage, etc. */
resume();           /* functions decrypt on next call */
```

### Supported C2 Frameworks

| Framework | Integration |
|-----------|-------------|
| Cobalt Strike | Crystal-Kit or UDRL with PICO loading |
| Sliver | CrystalSliver |
| Adaptix | Maverick / StealthPalace |
| Mythic | Xenon agent |
| Custom | Any loader using LibTCG |

## API Reference

| Function | Description |
|----------|-------------|
| `go()` | PICO entry point — resolves VirtualProtect, sets code base |
| `workmask_enter(meta)` | Decrypt function body (refCount 0→1 triggers decrypt) |
| `workmask_exit(meta)` | Re-encrypt function body (refCount→0 triggers encrypt) |
| `workmask_suspend()` | Re-encrypt ALL decrypted functions (call before sleep) |
| `workmask_resume()` | Clear suspend flag (functions decrypt on next enter) |
| `WORKMASK_CALL(meta, func, ...)` | Macro: enter + call + exit in one shot |
| `WORKMASK_CALL_RET(ret, meta, func, ...)` | Same but captures return value |
| `DECLARE_WORKMASK_META(name, key)` | Declare a HIRMETA_ENTRY for a function |

## HIRMETA_ENTRY Layout (32 bytes)

```
+0x00  int32_t   codeOffset      Offset from code base to function body
+0x04  uint32_t  funcSize        Size in bytes (0xDEADBEEF = unpatched)
+0x08  uint32_t  xorKey          4-byte rolling XOR key
+0x0C  uint32_t  prologueSkip    Bytes to skip before encrypted region
+0x10  long      refCount        Atomic reference count
+0x14  uint32_t  flags           WM_FLAG_ENABLED | WM_FLAG_DECRYPTED
+0x18  uint8_t   reserved[8]     Padding
```

## Acknowledgments

- [Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo) by MDSec — the original LLVM-based self-masking technique
- [Crystal Palace](https://www.cobaltstrike.com/product/crystal-palace) by Raphael Mudge — PIC linker and PICO format
- [emerald_template](https://github.com/0xTriboulet/emerald_template) by 0xTriboulet — Crystal Palace project template
- [The Tradecraft Garden](https://www.cobaltstrike.com/product/the-tradecraft-garden) — LibTCG runtime
