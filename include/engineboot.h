#ifndef __ENGINEBOOT_H
#define __ENGINEBOOT_H
#pragma once
#pragma pack(push, 1)

#define BOOTENGINE_PARAMS_VERSION 0x8E00

enum {
    BOOT_CACHEENABLED           = 1 << 0,
    BOOT_NOFILECHANGES          = 1 << 3,
    BOOT_ENABLECALLISTO         = 1 << 6,
    BOOT_REALTIMESIGS           = 1 << 8,
    BOOT_DISABLENOTIFICATION    = 1 << 9,
    BOOT_CLOUDBHEAVIORBLOCK     = 1 << 10,
    BOOT_ENABLELOGGING          = 1 << 12,
    BOOT_ENABLEBETA             = 1 << 16,
    BOOT_ENABLEIEV              = 1 << 17,
    BOOT_ENABLEMANAGED          = 1 << 19,
};

enum {
    BOOT_ATTR_NORMAL     = 1 << 0,
    BOOT_ATTR_ISXBAC     = 1 << 2,
};

enum {
    ENGINE_UNPACK               = 1 << 1,
    ENGINE_HEURISTICS           = 1 << 3,
    ENGINE_DISABLETHROTTLING    = 1 << 11,
    ENGINE_PARANOID             = 1 << 12,
    ENGINE_DISABLEANTISPYWARE   = 1 << 15,
    ENGINE_DISABLEANTIVIRUS     = 1 << 16,
    ENGINE_DISABLENETWORKDRIVES = 1 << 20,
};

typedef struct _ENGINE_INFO {
    DWORD   field_0;
    DWORD   field_4;    // Possibly Signature UNIX time?
    DWORD   field_8;
    DWORD   field_C;
} ENGINE_INFO, *PENGINE_INFO;

typedef struct _ENGINE_CONFIG {
    DWORD EngineFlags;
    PWCHAR Inclusions;      // Example, "*.zip"
    PVOID Exceptions;
    PWCHAR UnknownString2;
    PWCHAR QuarantineLocation;
    DWORD field_14;
    DWORD field_18;
    DWORD field_1C;
    DWORD field_20;
    DWORD field_24;
    DWORD field_28;
    DWORD field_2C;         // Setting this seems to cause packer to be reported.
    DWORD field_30;
    DWORD field_34;
    PCHAR UnknownAnsiString1;
    PCHAR UnknownAnsiString2;
} ENGINE_CONFIG, *PENGINE_CONFIG;

typedef struct _ENGINE_CONTEXT {
    DWORD   field_0;
} ENGINE_CONTEXT, *PENGINE_CONTEXT;

typedef struct _BOOTENGINE_PARAMS {
    DWORD           ClientVersion;
    PWCHAR          SignatureLocation;
    PVOID           SpynetSource;
    PENGINE_CONFIG  EngineConfig;
    PENGINE_INFO    EngineInfo;
    PWCHAR          ScanReportLocation;
    DWORD           BootFlags;
    PWCHAR          LocalCopyDirectory;
    PWCHAR          OfflineTargetOS;
    CHAR            ProductString[16];
    DWORD           field_34;
    PVOID           GlobalCallback;
    PENGINE_CONTEXT EngineContext;
    DWORD           AvgCpuLoadFactor;
    CHAR            field_44[16];
    PWCHAR          SpynetReportingGUID;
    PWCHAR          SpynetVersion;
    PWCHAR          NISEngineVersion;
    PWCHAR          NISSignatureVersion;
    DWORD           FlightingEnabled;
    DWORD           FlightingLevel;
    PVOID           DynamicConfig;
    DWORD           AutoSampleSubmission;
    DWORD           EnableThreatLogging;
    PWCHAR          ProductName;
    DWORD           PassiveMode;
    DWORD           SenseEnabled;
    PWCHAR          SenseOrgId;
    DWORD           Attributes;
    DWORD           BlockAtFirstSeen;
    DWORD           PUAProtection;
    DWORD           SideBySidePassiveMode;
} BOOTENGINE_PARAMS, *PBOOTENGINE_PARAMS;

#pragma pack(pop)
#endif // __ENGINEBOOT_H
