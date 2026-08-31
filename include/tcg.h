#pragma once
#ifndef TCG_H
#define TCG_H

#ifdef _DEBUG
#include <windows.h>
#else
#include "helpers.h"
#endif

/* IMPORTFUNCS -- passed to PicoLoad for API resolution */
typedef struct _IMPORTFUNCS {
    HMODULE (WINAPI *LoadLibraryA)(LPCSTR);
    FARPROC (WINAPI *GetProcAddress)(HMODULE, LPCSTR);
} IMPORTFUNCS;

/* LibTCG API -- provided by merging libtcg in the spec file */
size_t PicoCodeSize(char* src);
size_t PicoDataSize(char* src);
void   PicoLoad(IMPORTFUNCS* funcs, char* src, char* dstCode, char* dstData);
void*  PicoEntryPoint(char* src, char* code);
void*  PicoGetExport(char* code, unsigned int tag);

#endif /* TCG_H */
