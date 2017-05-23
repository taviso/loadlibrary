#ifndef __OPENSCAN_H
#define __OPENSCAN_H
#pragma once
#pragma pack(push, 1)

#define OPENSCAN_VERSION 0x2C6D

enum {
    SCANSOURCE_NOTASOURCE               = 0,
    SCANSOURCE_SCHEDULED                = 1,
    SCANSOURCE_ONDEMAND                 = 2,
    SCANSOURCE_RTP                      = 3,
    SCANSOURCE_IOAV_WEB                 = 4,
    SCANSOURCE_IOAV_FILE                = 5,
    SCANSOURCE_CLEAN                    = 6,
    SCANSOURCE_UCL                      = 7,
    SCANSOURCE_RTSIG                    = 8,
    SCANSOURCE_SPYNETREQUEST            = 9,
    SCANSOURCE_INFECTIONRESCAN          = 0x0A,
    SCANSOURCE_CACHE                    = 0x0B,
    SCANSOURCE_UNK_TELEMETRY            = 0x0C,
    SCANSOURCE_IEPROTECT                = 0x0D,
    SCANSOURCE_ELAM                     = 0x0E,
    SCANSOURCE_LOCAL_ATTESTATION        = 0x0F,
    SCANSOURCE_REMOTE_ATTESTATION       = 0x10,
    SCANSOURCE_HEARTBEAT                = 0x11,
    SCANSOURCE_MAINTENANCE              = 0x12,
    SCANSOURCE_MPUT                     = 0x13,
    SCANSOURCE_AMSI                     = 0x14,
    SCANSOURCE_STARTUP                  = 0x15,
    SCANSOURCE_ADDITIONAL_ACTIONS       = 0x16,
    SCANSOURCE_AMSI_UAC                 = 0x17,
    SCANSOURCE_GENSTREAM                = 0x18,
    SCANSOURCE_REPORTLOWFI              = 0x19,
    SCANSOURCE_REPORTINTERNALDETECTION  = 0x19,
    SCANSOURCE_SENSE                    = 0x1A,
    SCANSOURCE_XBAC                     = 0x1B,
};

typedef struct _OPENSCAN_PARAMS {
    DWORD   Version;
    DWORD   ScanSource;
    DWORD   Flags;
    DWORD   field_C;
    DWORD   field_10;
    DWORD   field_14;
    DWORD   field_18;
    DWORD   field_1C;
    GUID    ScanID;
    DWORD   field_30;
    DWORD   field_34;
    DWORD   field_38;
    DWORD   field_3C;
    DWORD   field_40;
    DWORD   field_44;
} OPENSCAN_PARAMS, *POPENSCAN_PARAMS;

#pragma pack(pop)
#endif // __OPENSCAN_H
