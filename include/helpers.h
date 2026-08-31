#pragma once
#ifndef HELPERS_H
#define HELPERS_H

#include <stdint.h>
#include <stddef.h>

#ifdef _DEBUG
#include <windows.h>
#include <string.h>
#define pic_memset(dst, val, sz) memset((dst), (val), (sz))
#define pic_memcpy(dst, src, sz) memcpy((dst), (src), (sz))
#define pic_strlen(s)            strlen((s))
#else
/* PIC-safe implementations - no libc dependency */

/* Windows type definitions for PIC mode */
#ifndef WINAPI
#define WINAPI __stdcall
#endif

#ifndef WINBASEAPI
#define WINBASEAPI __declspec(dllimport)
#endif

typedef void*          LPVOID;
typedef const void*    LPCVOID;
typedef unsigned long  DWORD;
typedef DWORD*         PDWORD;
typedef int            BOOL;
typedef unsigned short WORD;
typedef unsigned char  BYTE;
typedef long           LONG;
typedef const char*    LPCSTR;
typedef char*          LPSTR;
typedef void*          HANDLE;
typedef void*          HMODULE;
typedef void*          FARPROC;
typedef size_t         SIZE_T;

#define TRUE  1
#define FALSE 0
#ifndef NULL
#define NULL  ((void*)0)
#endif

#define PAGE_READWRITE       0x04
#define PAGE_EXECUTE_READ    0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define MEM_COMMIT           0x1000
#define MEM_RESERVE          0x2000
#define MEM_RELEASE          0x8000

static inline void pic_memset(void* dst, int val, size_t sz) {
    unsigned char* p = (unsigned char*)dst;
    for (size_t i = 0; i < sz; i++) p[i] = (unsigned char)val;
}

static inline void pic_memcpy(void* dst, const void* src, size_t sz) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < sz; i++) d[i] = s[i];
}

static inline size_t pic_strlen(const char* s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static inline int pic_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return *(unsigned char*)a - *(unsigned char*)b;
}

#endif /* _DEBUG */

/* Compiler intrinsics for atomic operations (position-independent, no API call) */
#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic(_InterlockedIncrement)
#pragma intrinsic(_InterlockedDecrement)
#pragma intrinsic(_InterlockedExchange)
#pragma intrinsic(_InterlockedCompareExchange)
#else
/* GCC/Clang builtins */
#define _InterlockedIncrement(p)         __sync_add_and_fetch((p), 1)
#define _InterlockedDecrement(p)         __sync_sub_and_fetch((p), 1)
#define _InterlockedExchange(p, v)       __sync_lock_test_and_set((p), (v))
#define _InterlockedCompareExchange(p, e, c) __sync_val_compare_and_swap((p), (c), (e))
#endif

#endif /* HELPERS_H */
