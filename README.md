# Hiraishin WorkMask

Per-function encrypt-at-rest for Crystal Palace PICOs. Function bodies are XOR-encrypted in the binary and only decrypted in memory when actively executing — re-encrypted the instant they return. Invisible to memory scanners, YARA rules, and static analysis at rest.

Inspired by [MDSec Function Peekaboo](https://www.mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/). Built as a standalone [Crystal Palace](https://www.cobaltstrike.com/product/crystal-palace) PICO.

## How It Works

```
AT REST          workmask_enter()        EXECUTING        workmask_exit()         AT REST
┌──────────┐    ┌──────────────────┐    ┌──────────┐    ┌──────────────────┐    ┌──────────┐
│ E3 29 4E │───>│ VirtualProtect RW│───>│ 49 89 CA │───>│ VirtualProtect RW│───>│ E3 29 4E │
│ D3 23 71 │    │ XOR decrypt      │    │ 49 89 D1 │    │ XOR encrypt      │    │ D3 23 71 │
│ CC 1F 78 │    │ VirtualProtect RX│    │ 48 85 D2 │    │ VirtualProtect RX│    │ CC 1F 78 │
│ (garbage)│    └──────────────────┘    │  (x64)   │    └──────────────────┘    │ (garbage)│
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
