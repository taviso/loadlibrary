#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <search.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

typedef struct _JOBOBJECT_BASIC_LIMIT_INFORMATION {
  LARGE_INTEGER PerProcessUserTimeLimit;
  LARGE_INTEGER PerJobUserTimeLimit;
  DWORD         LimitFlags;
  SIZE_T        MinimumWorkingSetSize;
  SIZE_T        MaximumWorkingSetSize;
  DWORD         ActiveProcessLimit;
  ULONG_PTR     Affinity;
  DWORD         PriorityClass;
  DWORD         SchedulingClass;
} JOBOBJECT_BASIC_LIMIT_INFORMATION, *PJOBOBJECT_BASIC_LIMIT_INFORMATION;

typedef struct _IO_COUNTERS {
  ULONGLONG ReadOperationCount;
  ULONGLONG WriteOperationCount;
  ULONGLONG OtherOperationCount;
  ULONGLONG ReadTransferCount;
  ULONGLONG WriteTransferCount;
  ULONGLONG OtherTransferCount;
} IO_COUNTERS;

typedef struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
  JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
  IO_COUNTERS                       IoInfo;
  SIZE_T                            ProcessMemoryLimit;
  SIZE_T                            JobMemoryLimit;
  SIZE_T                            PeakProcessMemoryUsed;
  SIZE_T                            PeakJobMemoryUsed;
} JOBOBJECT_EXTENDED_LIMIT_INFORMATION, *PJOBOBJECT_EXTENDED_LIMIT_INFORMATION;

STATIC WINAPI BOOL QueryInformationJobObject(
  HANDLE             hJob,
  DWORD JobObjectInformationClass,
  LPVOID             lpJobObjectInformation,
  DWORD              cbJobObjectInformationLength,
  LPDWORD            lpReturnLength
){
  DebugLog("%d %d", hJob, JobObjectInformationClass);
  if ( JobObjectInformationClass == 9) {
    PJOBOBJECT_EXTENDED_LIMIT_INFORMATION info = (PJOBOBJECT_EXTENDED_LIMIT_INFORMATION)lpJobObjectInformation;

    info->BasicLimitInformation.LimitFlags = 0;
    info->PeakProcessMemoryUsed=0x41;
    info->PeakJobMemoryUsed=0x41;
  }
  return true;
}

DECLARE_CRT_EXPORT("QueryInformationJobObject", QueryInformationJobObject);
