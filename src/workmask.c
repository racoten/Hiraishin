/*
 * workmask.c -- Hiraishin WorkMask PICO Runtime
 *
 * Crystal Palace Position-Independent Code Object implementing
 * per-function encrypt-at-rest. Functions marked for protection
 * have their bodies XOR-encrypted in the final binary. At runtime,
 * atomic reference counting ensures thread-safe decrypt-on-enter /
 * re-encrypt-on-exit semantics.
 *
 * Inspired by MDSec Function Peekaboo and Minato Hiraishin.
 *
 * Build: x86_64-w64-mingw32-gcc -DWIN_X64 -c -masm=intel -O1
 *        -fno-toplevel-reorder -fno-jump-tables -fno-exceptions
 *        -fno-stack-protector -I../include -o ../bin/workmask.x64.o workmask.c
 */

#include "workmask.h"
#include "workmask_dfr.h"

/* ─── Global state (lives in .data section of the PICO) ─────────────── */

WORKMASK_STATE g_wmState = { 0 };

/* ─── Internal: XOR engine ──────────────────────────────────────────── */

static void workmask_xor(void* addr, uint32_t size, uint32_t key) {
    uint8_t* p = (uint8_t*)addr;
    uint8_t k[4];
    k[0] = (uint8_t)(key);
    k[1] = (uint8_t)(key >> 8);
    k[2] = (uint8_t)(key >> 16);
    k[3] = (uint8_t)(key >> 24);

    for (uint32_t i = 0; i < size; i++) {
        p[i] ^= k[i & 3];
    }
}

/* ─── Internal: compute function VA from metadata entry ─────────────── */

static void* workmask_func_addr(HIRMETA_ENTRY* meta) {
    if (!g_wmState.codeBase) return NULL;
    return (void*)((uint8_t*)g_wmState.codeBase + meta->codeOffset + meta->prologueSkip);
}

/* ─── go() -- PICO entry point ──────────────────────────────────────── */

void go(void) {
    /*
     * Resolve VirtualProtect. In a Crystal Palace PICO loaded via
     * PicoLoad(), DFR symbols are already resolved. But we also
     * cache the pointer in g_wmState for the XOR engine to use
     * without repeated DFR lookups.
     *
     * We also need to determine the code region base address.
     * In PICO context, the loader passes this via PicoEntryPoint(),
     * so go() itself IS at the start of the code region (offset 0
     * when +gofirst is used in the spec file).
     */

    /* Cache VirtualProtect pointer */
    HMODULE hKernel32 = KERNEL32_GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        g_wmState.vpProtect = (void*)KERNEL32_GetProcAddress(hKernel32, "VirtualProtect");
    }

    /*
     * Compute code region base address.
     * The go() function is placed at offset 0 of the code region
     * by Crystal Palace's +gofirst. We use it as the base reference
     * for all codeOffset calculations in HIRMETA_ENTRY.
     *
     * Position-independent technique: use the address of go() itself.
     * Since go() is at code offset 0 (per spec file ordering), its
     * runtime address IS the code base.
     */
    g_wmState.codeBase = (void*)go;

    /* Mark initialization complete */
    _InterlockedExchange(&g_wmState.initialized, 1);
}

/* ─── workmask_enter() -- decrypt on first entry ────────────────────── */

void workmask_enter(HIRMETA_ENTRY* meta) {
    if (!meta) return;
    if (!g_wmState.initialized) return;
    if (!(meta->flags & WM_FLAG_ENABLED)) return;

    /* If suspended (sleep obfuscation active), no-op */
    if (g_wmState.suspended) return;

    /* funcSize sentinel check -- unpatched metadata */
    if (meta->funcSize == 0 || meta->funcSize == 0xDEADBEEF) return;

    /* Atomic increment -- capture PREVIOUS value */
    long prev = _InterlockedIncrement(&meta->refCount);
    /* _InterlockedIncrement returns the NEW value, so prev-1 was the old */

    if (prev == 1) {
        /* First entrant: decrypt the function body */
        void* funcAddr = workmask_func_addr(meta);
        if (!funcAddr) return;

        DWORD oldProt = 0;
        if (g_wmState.vpProtect) {
            typedef BOOL (WINAPI *VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
            VirtualProtect_t vpFn = (VirtualProtect_t)g_wmState.vpProtect;

            vpFn(funcAddr, meta->funcSize, PAGE_READWRITE, &oldProt);
            workmask_xor(funcAddr, meta->funcSize, meta->xorKey);
            vpFn(funcAddr, meta->funcSize, PAGE_EXECUTE_READ, &oldProt);
        } else {
            /* Fallback: use DFR-resolved VirtualProtect */
            KERNEL32_VirtualProtect(funcAddr, meta->funcSize, PAGE_READWRITE, &oldProt);
            workmask_xor(funcAddr, meta->funcSize, meta->xorKey);
            KERNEL32_VirtualProtect(funcAddr, meta->funcSize, PAGE_EXECUTE_READ, &oldProt);
        }

        meta->flags |= WM_FLAG_DECRYPTED;
    }
    /* If prev > 1: function already decrypted by another thread, skip */
}

/* ─── workmask_exit() -- re-encrypt on last exit ────────────────────── */

void workmask_exit(HIRMETA_ENTRY* meta) {
    if (!meta) return;
    if (!g_wmState.initialized) return;
    if (!(meta->flags & WM_FLAG_ENABLED)) return;

    if (g_wmState.suspended) return;

    if (meta->funcSize == 0 || meta->funcSize == 0xDEADBEEF) return;

    /* Atomic decrement -- capture NEW value */
    long remaining = _InterlockedDecrement(&meta->refCount);

    if (remaining == 0) {
        /* Last exiter: re-encrypt the function body */
        void* funcAddr = workmask_func_addr(meta);
        if (!funcAddr) return;

        DWORD oldProt = 0;
        if (g_wmState.vpProtect) {
            typedef BOOL (WINAPI *VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
            VirtualProtect_t vpFn = (VirtualProtect_t)g_wmState.vpProtect;

            vpFn(funcAddr, meta->funcSize, PAGE_READWRITE, &oldProt);
            workmask_xor(funcAddr, meta->funcSize, meta->xorKey);
            vpFn(funcAddr, meta->funcSize, PAGE_EXECUTE_READ, &oldProt);
        } else {
            KERNEL32_VirtualProtect(funcAddr, meta->funcSize, PAGE_READWRITE, &oldProt);
            workmask_xor(funcAddr, meta->funcSize, meta->xorKey);
            KERNEL32_VirtualProtect(funcAddr, meta->funcSize, PAGE_EXECUTE_READ, &oldProt);
        }

        meta->flags &= ~WM_FLAG_DECRYPTED;
    }
    /* If remaining > 0: other threads still executing, skip */
}

/* ─── workmask_suspend() -- re-encrypt all for sleep obfuscation ────── */

void workmask_suspend(void) {
    _InterlockedExchange(&g_wmState.suspended, 1);

    if (!g_wmState.initialized) return;
    if (g_wmState.entryCount == 0) return;

    /* Walk all metadata entries */
    HIRMETA_ENTRY* entries = (HIRMETA_ENTRY*)((uint8_t*)&g_wmState + g_wmState.metaOffset);

    for (uint32_t i = 0; i < g_wmState.entryCount; i++) {
        HIRMETA_ENTRY* meta = &entries[i];

        if (!(meta->flags & WM_FLAG_ENABLED)) continue;
        if (!(meta->flags & WM_FLAG_DECRYPTED)) continue;
        if (meta->funcSize == 0 || meta->funcSize == 0xDEADBEEF) continue;

        /* Reset refCount to 0 */
        _InterlockedExchange(&meta->refCount, 0);

        /* Re-encrypt */
        void* funcAddr = workmask_func_addr(meta);
        if (!funcAddr) continue;

        DWORD oldProt = 0;
        if (g_wmState.vpProtect) {
            typedef BOOL (WINAPI *VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
            VirtualProtect_t vpFn = (VirtualProtect_t)g_wmState.vpProtect;

            vpFn(funcAddr, meta->funcSize, PAGE_READWRITE, &oldProt);
            workmask_xor(funcAddr, meta->funcSize, meta->xorKey);
            vpFn(funcAddr, meta->funcSize, PAGE_EXECUTE_READ, &oldProt);
        } else {
            KERNEL32_VirtualProtect(funcAddr, meta->funcSize, PAGE_READWRITE, &oldProt);
            workmask_xor(funcAddr, meta->funcSize, meta->xorKey);
            KERNEL32_VirtualProtect(funcAddr, meta->funcSize, PAGE_EXECUTE_READ, &oldProt);
        }

        meta->flags &= ~WM_FLAG_DECRYPTED;
    }
}

/* ─── workmask_resume() -- clear suspend flag ───────────────────────── */

void workmask_resume(void) {
    /* Functions remain encrypted -- they will decrypt on-demand via enter() */
    _InterlockedExchange(&g_wmState.suspended, 0);
}
