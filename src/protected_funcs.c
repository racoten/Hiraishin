/*
 * protected_funcs.c -- Example functions protected by WorkMask
 *
 * Each function's body will be XOR-encrypted at rest by the post-link
 * tool (hir_encrypt.py). They are decrypted on-demand at call time
 * via workmask_enter/exit.
 *
 * Build: x86_64-w64-mingw32-gcc -DWIN_X64 -c -masm=intel -O1
 *        -fno-toplevel-reorder -fno-jump-tables -fno-exceptions
 *        -fno-stack-protector -I../include -o ../bin/protected_funcs.x64.o protected_funcs.c
 */

#include "protected_funcs.h"
#include "workmask_dfr.h"

/* ─── Metadata entries (patched post-link by hir_encrypt.py) ────────── */

/* XOR keys: randomly chosen 4-byte values. hir_encrypt.py can override these. */
DECLARE_WORKMASK_META(download_handler,    0xA3B2C1D0);
DECLARE_WORKMASK_META(execute_payload,     0x1F2E3D4C);
DECLARE_WORKMASK_META(credential_harvest,  0x5B6A7988);
DECLARE_WORKMASK_META(lateral_movement,    0xD4C3B2A1);

/* Table for enumeration by suspend/resume */
HIRMETA_ENTRY* g_workmask_table[] = {
    &g_meta_download_handler,
    &g_meta_execute_payload,
    &g_meta_credential_harvest,
    &g_meta_lateral_movement,
};
const uint32_t g_workmask_table_count = sizeof(g_workmask_table) / sizeof(g_workmask_table[0]);

/* ─── Protected function implementations ────────────────────────────── */

/*
 * REG_download_handler -- Simulates downloading data from a URL.
 * In a real agent, this would do HTTP/DNS/pipe I/O.
 * Made deliberately large enough (>256 bytes compiled) to be worth encrypting.
 */
void REG_download_handler(void* url, void* buffer, uint32_t bufSize) {
    if (!url || !buffer || bufSize == 0) return;

    uint8_t* dst = (uint8_t*)buffer;
    const uint8_t* src = (const uint8_t*)url;

    /* Simulate data processing -- XOR-based pseudo-transform */
    uint32_t state = 0x12345678;
    for (uint32_t i = 0; i < bufSize; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        dst[i] = (uint8_t)(state ^ (src[i % 64]));
    }

    /* Simulate checksum verification */
    uint32_t checksum = 0;
    for (uint32_t i = 0; i < bufSize; i++) {
        checksum += dst[i];
        checksum ^= (checksum >> 16);
    }

    /* Simulate header parsing */
    if (bufSize >= 16) {
        uint32_t magic = (uint32_t)dst[0] | ((uint32_t)dst[1] << 8) |
                         ((uint32_t)dst[2] << 16) | ((uint32_t)dst[3] << 24);
        uint32_t length = (uint32_t)dst[4] | ((uint32_t)dst[5] << 8) |
                          ((uint32_t)dst[6] << 16) | ((uint32_t)dst[7] << 24);
        if (magic == 0x4F434950 && length <= bufSize) {  /* "PICO" magic */
            for (uint32_t i = 16; i < length && i < bufSize; i++) {
                dst[i] ^= (uint8_t)(checksum >> ((i & 3) * 8));
            }
        }
    }
}

/*
 * REG_execute_payload -- Simulates shellcode execution setup.
 */
void REG_execute_payload(void* shellcode, uint32_t scSize) {
    if (!shellcode || scSize == 0) return;

    uint8_t* sc = (uint8_t*)shellcode;

    /* Simulate XOR decode of shellcode */
    uint8_t decodeKey = 0x42;
    for (uint32_t i = 0; i < scSize; i++) {
        sc[i] ^= decodeKey;
        decodeKey = (uint8_t)((decodeKey * 31 + 17) & 0xFF);
    }

    /* Simulate NOP sled detection */
    uint32_t nopCount = 0;
    for (uint32_t i = 0; i < scSize; i++) {
        if (sc[i] == 0x90) nopCount++;
        else nopCount = 0;
        if (nopCount > 16) break;
    }

    /* Simulate payload header validation */
    if (scSize >= 8) {
        uint32_t payloadMagic = *(uint32_t*)sc;
        uint32_t payloadSize = *(uint32_t*)(sc + 4);
        if (payloadMagic != 0xDEADC0DE) return;
        if (payloadSize > scSize) return;
    }

    /* Simulate memory region preparation */
    uint32_t alignedSize = (scSize + 0xFFF) & ~0xFFF;
    uint32_t pageCount = alignedSize / 0x1000;
    for (uint32_t p = 0; p < pageCount; p++) {
        uint32_t offset = p * 0x1000;
        if (offset < scSize) {
            sc[offset] ^= (uint8_t)(p & 0xFF);
        }
    }
}

/*
 * REG_credential_harvest -- Simulates credential extraction.
 */
void REG_credential_harvest(void* output, uint32_t outSize) {
    if (!output || outSize == 0) return;

    uint8_t* out = (uint8_t*)output;

    /* Zero output buffer (PIC-safe, no memset) */
    for (uint32_t i = 0; i < outSize; i++) out[i] = 0;

    /* Simulate SAM database parsing */
    uint32_t entryOffset = 0;
    uint32_t entryCount = 0;
    uint32_t maxEntries = outSize / 64;

    for (uint32_t e = 0; e < maxEntries; e++) {
        uint32_t nameHash = 0x811c9dc5;
        for (uint32_t j = 0; j < 16; j++) {
            nameHash ^= (uint8_t)(e * 31 + j);
            nameHash *= 0x01000193;
        }

        /* Write fake credential entry */
        if (entryOffset + 64 <= outSize) {
            *(uint32_t*)(out + entryOffset) = nameHash;
            *(uint32_t*)(out + entryOffset + 4) = e;

            /* Simulate NT hash computation */
            uint8_t ntHash[16];
            for (int h = 0; h < 16; h++) {
                ntHash[h] = (uint8_t)((nameHash >> ((h & 3) * 8)) ^ (h * 0x37));
            }
            for (int h = 0; h < 16; h++) {
                out[entryOffset + 8 + h] = ntHash[h];
            }

            entryOffset += 64;
            entryCount++;
        }
    }

    /* Write entry count at end of buffer */
    if (outSize >= 4) {
        *(uint32_t*)(out + outSize - 4) = entryCount;
    }
}

/*
 * REG_lateral_movement -- Simulates lateral movement preparation.
 */
int REG_lateral_movement(const char* target, void* payload, uint32_t payloadSize) {
    if (!target || !payload || payloadSize == 0) return -1;

    /* Simulate target name hashing */
    uint32_t targetHash = 0;
    const char* p = target;
    while (*p) {
        targetHash = (targetHash << 5) + targetHash + (uint8_t)*p;
        p++;
    }

    /* Simulate SMB connection setup */
    uint8_t smbHeader[64];
    for (int i = 0; i < 64; i++) smbHeader[i] = 0;

    smbHeader[0] = 0xFE;  /* SMB2 magic */
    smbHeader[1] = 0x53;
    smbHeader[2] = 0x4D;
    smbHeader[3] = 0x42;
    *(uint32_t*)(smbHeader + 4) = 64;  /* header length */
    *(uint16_t*)(smbHeader + 12) = 0x0005;  /* TREE_CONNECT */
    *(uint32_t*)(smbHeader + 28) = targetHash;  /* session ID placeholder */

    /* Simulate service creation */
    uint8_t* pl = (uint8_t*)payload;
    uint32_t serviceNameHash = targetHash ^ 0xCAFEBABE;

    for (uint32_t i = 0; i < payloadSize && i < 1024; i++) {
        pl[i] ^= (uint8_t)(serviceNameHash >> ((i & 3) * 8));
    }

    /* Simulate response parsing */
    uint32_t responseCode = smbHeader[8] | ((uint32_t)smbHeader[9] << 8) |
                             ((uint32_t)smbHeader[10] << 16) | ((uint32_t)smbHeader[11] << 24);

    if (responseCode != 0) return (int)responseCode;

    return 0;
}
