#pragma once
#ifndef WORKMASK_DFR_H
#define WORKMASK_DFR_H

#ifdef _DEBUG
/* Debug mode: use real Win32 imports */
#include <windows.h>
#define KERNEL32_VirtualProtect  VirtualProtect
#define KERNEL32_LoadLibraryA    LoadLibraryA
#define KERNEL32_GetProcAddress  GetProcAddress
#define KERNEL32_GetModuleHandleA GetModuleHandleA
#else
/* Release mode: Crystal Palace DFR convention */
/* These are resolved by Crystal Palace at link time via ror13 hashing */
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);

#define KERNEL32_VirtualProtect  KERNEL32$VirtualProtect
#define KERNEL32_LoadLibraryA    KERNEL32$LoadLibraryA
#define KERNEL32_GetProcAddress  KERNEL32$GetProcAddress
#define KERNEL32_GetModuleHandleA KERNEL32$GetModuleHandleA
#endif

#endif /* WORKMASK_DFR_H */
