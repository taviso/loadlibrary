#ifndef __SCANREPLY_H
#define __SCANREPLY_H
#pragma once
#pragma pack(push, 1)

// These are just guesses based on observed behaviour.
enum {
    SCAN_FILENAME        = 1 << 8,
    SCAN_ENCRYPTED       = 1 << 6,
    SCAN_MEMBERNAME      = 1 << 7,
    SCAN_FILETYPE        = 1 << 9,
    SCAN_TOPLEVEL        = 1 << 18,
    SCAN_PACKERSTART     = 1 << 19,
    SCAN_PACKEREND       = 1 << 12,
    SCAN_ISARCHIVE       = 1 << 16,
    SCAN_VIRUSFOUND      = 1 << 27,
    SCAN_CORRUPT         = 1 << 13,
    SCAN_UNKNOWN         = 1 << 15, // I dunno what this means
};

typedef struct _SCANSTRUCT {
    DWORD field_0;
    DWORD Flags;
    PCHAR FileName;
    CHAR  VirusName[28];
    DWORD field_28;
    DWORD field_2C;
    DWORD field_30;
    DWORD field_34;
    DWORD field_38;
    DWORD field_3C;
    DWORD field_40;
    DWORD field_44;
    DWORD field_48;
    DWORD field_4C;
    DWORD FileSize;
    DWORD field_54;
    DWORD UserPtr;
    DWORD field_5C;
    PCHAR MaybeFileName2;
    PWCHAR StreamName1;
    PWCHAR StreamName2;
    DWORD field_6C;
    DWORD ThreatId;             // Can be passed back to GetThreatInfo
} SCANSTRUCT, *PSCANSTRUCT;

typedef struct _SCAN_REPLY {
    DWORD   (*EngineScanCallback)(PSCANSTRUCT this);
    DWORD   field_4;
    DWORD   UserPtr;
    DWORD   field_C;
} SCAN_REPLY, *PSCAN_REPLY;

#pragma pack(pop)
#endif // __SCANREPLY_H

