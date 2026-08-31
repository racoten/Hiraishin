#pragma once
#ifndef WORKMASK_H
#define WORKMASK_H

#ifdef _DEBUG
#include <windows.h>
#else
#include "helpers.h"
#endif

#include <stdint.h>

/* Flags for HIRMETA_ENTRY.flags */
#define WM_FLAG_ENABLED      0x01
#define WM_FLAG_DECRYPTED    0x02
#define WM_FLAG_SUSPENDED    0x04

/* Export tags (ror13 hashes for PicoGetExport) */
#define TAG_WM_ENTER    0x1A2B3C4D   /* placeholder - real hash computed by Crystal Palace */
#define TAG_WM_EXIT     0x2B3C4D5E
#define TAG_WM_SUSPEND  0x3C4D5E6F
#define TAG_WM_RESUME   0x4D5E6F70

/*
 * Per-function metadata entry.
 * Layout: 32 bytes, aligned to 8-byte boundary.
 * One entry per protected function, stored in .data section.
 * The post-link tool (hir_encrypt.py) patches codeOffset and funcSize
 * by locating g_meta_* symbols in the COFF symbol table and writing
 * the correct values into the struct fields. It also encrypts function
 * bodies and records everything in a JSON manifest for verification.
 */
typedef struct _HIRMETA_ENTRY {
    int32_t   codeOffset;      /* +0x00: signed offset from code region base to function body */
    uint32_t  funcSize;        /* +0x04: size of encrypted body in bytes (0xDEADBEEF = unpatched) */
    uint32_t  xorKey;          /* +0x08: 4-byte rolling XOR key */
    uint32_t  prologueSkip;    /* +0x0C: bytes to skip at function start (prologue left in cleartext) */
    volatile long refCount;    /* +0x10: atomic reference count for thread safety */
    uint32_t  flags;           /* +0x14: WM_FLAG_* bitfield */
    uint8_t   reserved[8];     /* +0x18: padding to 32 bytes */
} HIRMETA_ENTRY;

/*
 * Global WorkMask state, stored at the start of the PICO's .data region.
 */
typedef struct _WORKMASK_STATE {
    volatile long suspended;     /* +0x00: global suspend flag (1=suspended) */
    volatile long initialized;   /* +0x04: initialization complete flag */
    void*         vpProtect;     /* +0x08: cached VirtualProtect function pointer */
    void*         codeBase;      /* +0x10: base address of code region */
    uint32_t      entryCount;    /* +0x18: number of HIRMETA_ENTRY records */
    uint32_t      metaOffset;    /* +0x1C: offset from data base to first HIRMETA_ENTRY */
    uint8_t       reserved[16];  /* +0x20: future use */
} WORKMASK_STATE;

/* Public API */
void go(void);
void workmask_enter(HIRMETA_ENTRY* meta);
void workmask_exit(HIRMETA_ENTRY* meta);
void workmask_suspend(void);
void workmask_resume(void);

/*
 * Convenience macro for calling a protected function.
 * Usage: WORKMASK_CALL(g_meta_myfunc, my_function, arg1, arg2);
 */
#define WORKMASK_CALL(meta, func, ...) \
    do { workmask_enter(&(meta)); func(__VA_ARGS__); workmask_exit(&(meta)); } while(0)

/*
 * Variant that captures a return value.
 * Usage: int ret; WORKMASK_CALL_RET(ret, g_meta_myfunc, my_function, arg1, arg2);
 */
#define WORKMASK_CALL_RET(retvar, meta, func, ...) \
    do { workmask_enter(&(meta)); (retvar) = func(__VA_ARGS__); workmask_exit(&(meta)); } while(0)

/*
 * Macro to declare a HIRMETA_ENTRY for a protected function.
 * codeOffset is set to 0 (patched post-link), funcSize to 0xDEADBEEF (sentinel).
 * xorKey is set to a compile-time random value (or 0 to be patched by hir_encrypt.py).
 */
#define DECLARE_WORKMASK_META(name, key) \
    HIRMETA_ENTRY g_meta_##name = { 0, 0xDEADBEEF, (key), 0, 0, WM_FLAG_ENABLED, {0} }

#endif /* WORKMASK_H */
