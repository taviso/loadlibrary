/*
 *  Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#ifndef _WINNT_TYPES_H_
#define _WINNT_TYPES_H_

#define DLL_PROCESS_ATTACH              1
#define DLL_PROCESS_DETACH              0
#define DLL_THREAD_ATTACH               2
#define DLL_THREAD_DETACH               3

#define TRUE                            1
#define FALSE                           0

#define HANDLE                          PVOID
#define HMODULE                         PVOID
#define INVALID_HANDLE_VALUE            ((HANDLE)(-1))

#define PASSIVE_LEVEL                   0
#define APC_LEVEL                       1
#define DISPATCH_LEVEL                  2
#define DEVICE_LEVEL_BASE               4

/* soft interrupts / bottom-half's are disabled at SOFT_IRQL */
#define SOFT_IRQL                       (DEVICE_LEVEL_BASE + 1)
#define DIRQL                           (DEVICE_LEVEL_BASE + 2)

#define STATUS_WAIT_0                   0
#define STATUS_SUCCESS                  0
#define STATUS_ALERTED                  0x00000101
#define STATUS_TIMEOUT                  0x00000102
#define STATUS_PENDING                  0x00000103
#define STATUS_FAILURE                  0xC0000001
#define STATUS_NOT_IMPLEMENTED          0xC0000002
#define STATUS_INVALID_PARAMETER        0xC000000D
#define STATUS_INVALID_DEVICE_REQUEST   0xC0000010
#define STATUS_MORE_PROCESSING_REQUIRED 0xC0000016
#define STATUS_ACCESS_DENIED            0xC0000022
#define STATUS_BUFFER_TOO_SMALL         0xC0000023
#define STATUS_OBJECT_NAME_INVALID      0xC0000023
#define STATUS_MUTANT_NOT_OWNED         0xC0000046
#define STATUS_RESOURCES                0xC000009A
#define STATUS_DELETE_PENDING           0xC0000056
#define STATUS_INSUFFICIENT_RESOURCES   0xC000009A
#define STATUS_NOT_SUPPORTED            0xC00000BB
#define STATUS_INVALID_PARAMETER_2      0xC00000F0
#define STATUS_NO_MEMORY                0xC0000017
#define STATUS_CANCELLED                0xC0000120
#define STATUS_DEVICE_REMOVED           0xC00002B6
#define STATUS_DEVICE_NOT_CONNECTED     0xC000009D

#define STATUS_BUFFER_OVERFLOW          0x80000005

#define SL_PENDING_RETURNED             0x01
#define SL_INVOKE_ON_CANCEL             0x20
#define SL_INVOKE_ON_SUCCESS            0x40
#define SL_INVOKE_ON_ERROR              0x80

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04

#define IRP_MJ_DEVICE_CONTROL           0x0E
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0F
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x0E
#define IRP_MJ_PNP                      0x1b
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

#define IRP_MN_WAIT_WAKE                0x00
#define IRP_MN_POWER_SEQUENCE           0x01
#define IRP_MN_SET_POWER                0x02
#define IRP_MN_QUERY_POWER              0x03

#define IRP_MN_REGINFO                  0x08
#define IRP_MN_REGINFO_EX               0x0b

#define IRP_MN_START_DEVICE             0x00
#define IRP_MN_QUERY_REMOVE_DEVICE      0x01
#define IRP_MN_REMOVE_DEVICE            0x02
#define IRP_MN_CANCEL_REMOVE_DEVICE     0x03
#define IRP_MN_STOP_DEVICE              0x04
#define IRP_MN_QUERY_STOP_DEVICE        0x05
#define IRP_MN_CANCEL_STOP_DEVICE       0x06
#define IRP_MN_QUERY_DEVICE_RELATIONS   0x07
#define IRP_MN_QUERY_INTERFACE          0x08

#define IRP_BUFFERED_IO                 0x00000010
#define IRP_DEALLOCATE_BUFFER           0x00000020
#define IRP_INPUT_OPERATION             0x00000040

#define IRP_DEFFER_IO_COMPLETION        0x00000800

#define THREAD_WAIT_OBJECTS             3
#define MAX_WAIT_OBJECTS                64

#define LOW_PRIORITY                    0
#define LOW_REALTIME_PRIORITY           16
#define HIGH_PRIORITY                   31
#define MAXIMUM_PRIORITY                32

#define PROCESSOR_FEATURE_MAX           64

#define IO_NO_INCREMENT                 0

#define WMIREG_ACTION_REGISTER          1
#define WMIREG_ACTION_DEREGISTER        2
#define WMIREG_ACTION_REREGISTER        3
#define WMIREG_ACTION_UPDATE_GUIDS      4

#define WMIREGISTER                     0
#define WMIUPDATE                       1

#define noregparm __attribute__((regparm(0)))
#define regparm3 __attribute__((regparm(3)))
#define wstdcall __attribute__((__stdcall__, regparm(0)))
#define __packed __attribute__((packed))
#define wfastcall __attribute__((fastcall))
#define STATIC static
#define VOID void
#define WINAPI __attribute__((__stdcall__))

#define KI_USER_SHARED_DATA 0xffdf0000
#define MM_SHARED_USER_DATA_VA 0x7ffe0000

typedef uint8_t     BOOLEAN, BOOL;
typedef void       *PVOID;
typedef uint8_t     BYTE;
typedef uint8_t    *PBYTE;
typedef uint8_t    *LPBYTE;
typedef int8_t      CHAR;
typedef char       *PCHAR;
typedef uint8_t     UCHAR;
typedef uint8_t    *PUCHAR;
typedef uint16_t    SHORT;
typedef uint16_t    USHORT;
typedef uint16_t  *PUSHORT;
typedef uint16_t    WORD;
typedef int32_t     INT;
typedef uint32_t    UINT;
typedef uint32_t    DWORD, *PDWORD;
typedef int32_t     LONG;
typedef uint32_t    ULONG;
typedef uint32_t   *PULONG;
typedef int64_t     LONGLONG;
typedef uint64_t    ULONGLONG, *PULONGLONG;
typedef uint64_t    ULONGULONG;
typedef uint64_t    ULONG64;
typedef uint64_t    QWORD, *PQWORD;
typedef uint16_t    WCHAR, *PWCHAR;
typedef HANDLE     *PHANDLE;

typedef CHAR CCHAR;
typedef SHORT CSHORT;
typedef LONGLONG LARGE_INTEGER;

typedef LONG NTSTATUS;

typedef LONG KPRIORITY;
typedef LARGE_INTEGER PHYSICAL_ADDRESS;
typedef UCHAR KIRQL;
typedef CHAR KPROCESSOR_MODE;

/* ULONG_PTR is 32 bits on 32-bit platforms and 64 bits on 64-bit
 * platform, which is same as 'unsigned long' in Linux */
typedef unsigned long ULONG_PTR;

typedef size_t SIZE_T;
typedef ULONG_PTR KAFFINITY;
typedef ULONG ACCESS_MASK;

typedef ULONG_PTR PFN_NUMBER;
typedef ULONG SECURITY_INFORMATION;

/* non-negative numbers indicate success */
#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)

typedef struct _FILETIME {
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME, *PFILETIME;

typedef struct ansi_string {
        USHORT length;
        USHORT max_length;
        char *buf;
} ANSI_STRING, *PANSI_STRING;

typedef struct unicode_string {
        USHORT Length;
        USHORT MaximumLength;
        wchar_t *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

struct nt_slist {
        struct nt_slist *next;
};

union nt_slist_head {
        ULONGLONG align;
        struct {
                struct nt_slist *next;
                USHORT depth;
                USHORT sequence;
        };
};
typedef union nt_slist_head nt_slist_header;

struct nt_list {
        struct nt_list *next;
        struct nt_list *prev;
};

typedef ULONG_PTR NT_SPIN_LOCK;

enum kdpc_importance {LowImportance, MediumImportance, HighImportance};

struct kdpc;
typedef void (*DPC)(struct kdpc *kdpc, void *ctx, void *arg1,
                    void *arg2) wstdcall;
struct kdpc {
        SHORT type;
        UCHAR nr_cpu;
        UCHAR importance;
        struct nt_list list;
        DPC func;
        void *ctx;
        void *arg1;
        void *arg2;
        union {
                NT_SPIN_LOCK *lock;
                /* 'lock' is not used; 'queued' represents whether
                 * kdpc is queued or not */
                int queued;
        };
};

enum pool_type {
        NonPagedPool, PagedPool, NonPagedPoolMustSucceed, DontUseThisType,
        NonPagedPoolCacheAligned, PagedPoolCacheAligned,
        NonPagedPoolCacheAlignedMustS, MaxPoolType,
        NonPagedPoolSession = 32,
        PagedPoolSession = NonPagedPoolSession + 1,
        NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
        DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
        NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
        PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
        NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1
};

enum memory_caching_type_orig {
        MmFrameBufferCached = 2
};

enum memory_caching_type {
        MmNonCached = FALSE, MmCached = TRUE,
        MmWriteCombined = MmFrameBufferCached, MmHardwareCoherentCached,
        MmNonCachedUnordered, MmUSWCCached, MmMaximumCacheType
};

enum lock_operation {
        IoReadAccess, IoWriteAccess, IoModifyAccess
};

enum mode {
        KernelMode, UserMode, MaximumMode
};

struct mdl {
        struct mdl *next;
        CSHORT size;
        CSHORT flags;
        /* NdisFreeBuffer doesn't pass pool, so we store pool in
         * unused field 'process' */
        union {
                void *process;
                void *pool;
        };
        void *mappedsystemva;
        void *startva;
        ULONG bytecount;
        ULONG byteoffset;
};

#define MDL_MAPPED_TO_SYSTEM_VA         0x0001
#define MDL_PAGES_LOCKED                0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL     0x0004
#define MDL_ALLOCATED_FIXED_SIZE        0x0008
#define MDL_PARTIAL                     0x0010
#define MDL_PARTIAL_HAS_BEEN_MAPPED     0x0020
#define MDL_IO_PAGE_READ                0x0040
#define MDL_WRITE_OPERATION             0x0080
#define MDL_PARENT_MAPPED_SYSTEM_VA     0x0100
#define MDL_FREE_EXTRA_PTES             0x0200
#define MDL_IO_SPACE                    0x0800
#define MDL_NETWORK_HEADER              0x1000
#define MDL_MAPPING_CAN_FAIL            0x2000
#define MDL_ALLOCATED_MUST_SUCCEED      0x4000

#define MDL_POOL_ALLOCATED              0x0400
#define MDL_CACHE_ALLOCATED             0x8000

#define PAGE_START(ptr) ((void *)((ULONG_PTR)(ptr) & ~(PAGE_SIZE - 1)))
#define BYTE_OFFSET(ptr) ((ULONG)((ULONG_PTR)(ptr) & (PAGE_SIZE - 1)))

#define MmGetMdlByteCount(mdl) ((mdl)->bytecount)
#define MmGetMdlVirtualAddress(mdl) ((mdl)->startva + (mdl)->byteoffset)
#define MmGetMdlByteOffset(mdl) ((mdl)->byteoffset)
#define MmGetSystemAddressForMdl(mdl) ((mdl)->mappedsystemva)
#define MmGetSystemAddressForMdlSafe(mdl, priority) ((mdl)->mappedsystemva)
#define MmGetMdlPfnArray(mdl) ((PFN_NUMBER *)(mdl + 1))
#define MmInitializeMdl(mdl, baseva, length)                            \
do {                                                                    \
        (mdl)->next = NULL;                                             \
        (mdl)->size = MmSizeOfMdl(baseva, length);                      \
        (mdl)->flags = 0;                                               \
        (mdl)->startva = PAGE_START(baseva);                            \
        (mdl)->byteoffset = BYTE_OFFSET(baseva);                        \
        (mdl)->bytecount = length;                                      \
        (mdl)->mappedsystemva = baseva;                                 \
        TRACE4("%p %p %p %d %d", (mdl), baseva, (mdl)->startva, \
                  (mdl)->byteoffset, length);                           \
} while (0)

struct kdevice_queue_entry {
        struct nt_list list;
        ULONG sort_key;
        BOOLEAN inserted;
};

struct kdevice_queue {
        USHORT type;
        USHORT size;
        struct nt_list list;
        NT_SPIN_LOCK lock;
        BOOLEAN busy;
};

struct wait_context_block {
        struct kdevice_queue_entry wait_queue_entry;
        void *device_routine;
        void *device_context;
        ULONG num_regs;
        void *device_object;
        void *current_irp;
        void *buffer_chaining_dpc;
};

struct wait_block {
        struct nt_list list;
        struct task_struct *thread;
        void *object;
        int *wait_done;
        USHORT wait_key;
        USHORT wait_type;
};

struct dispatcher_header {
        UCHAR type;
        UCHAR absolute;
        UCHAR size;
        UCHAR inserted;
        LONG signal_state;
        struct nt_list wait_blocks;
};

enum event_type {
        NotificationEvent,
        SynchronizationEvent,
};

enum timer_type {
        NotificationTimer = NotificationEvent,
        SynchronizationTimer = SynchronizationEvent,
};

enum dh_type {
        NotificationObject = NotificationEvent,
        SynchronizationObject = SynchronizationEvent,
        MutexObject,
        SemaphoreObject,
        ThreadObject,
};

enum wait_type {
        WaitAll, WaitAny
};

/* objects that use dispatcher_header have it as the first field, so
 * whenever we need to initialize dispatcher_header, we can convert
 * that object into a nt_event and access dispatcher_header */
struct nt_event {
        struct dispatcher_header dh;
};

struct wrap_timer;

#define WRAP_TIMER_MAGIC 47697249

struct nt_timer {
        struct dispatcher_header dh;
        /* We can't fit Linux timer in this structure. Instead of
         * padding the nt_timer structure, we replace due_time field
         * with *wrap_timer and allocate memory for it when nt_timer is
         * initialized */
        union {
                ULONGLONG due_time;
                struct wrap_timer *wrap_timer;
        };
        struct nt_list nt_timer_list;
        struct kdpc *kdpc;
        union {
                LONG period;
                LONG wrap_timer_magic;
        };
};

struct nt_mutex {
        struct dispatcher_header dh;
        struct nt_list list;
        struct task_struct *owner_thread;
        BOOLEAN abandoned;
        BOOLEAN apc_disable;
};

struct nt_semaphore {
        struct dispatcher_header dh;
        LONG limit;
};

struct nt_thread {
        struct dispatcher_header dh;
        /* the rest in Windows is a long structure; since this
         * structure is opaque to drivers, we just define what we
         * need */
        int pid;
        NTSTATUS status;
        struct task_struct *task;
        struct nt_list irps;
        NT_SPIN_LOCK lock;
        KPRIORITY prio;
};

#define set_object_type(dh, type)       ((dh)->type = (type))
#define is_notify_object(dh)            ((dh)->type == NotificationObject)
#define is_synch_object(dh)             ((dh)->type == SynchronizationObject)
#define is_mutex_object(dh)             ((dh)->type == MutexObject)
#define is_semaphore_object(dh)         ((dh)->type == SemaphoreObject)
#define is_nt_thread_object(dh)         ((dh)->type == ThreadObject)

#define IO_TYPE_ADAPTER                         1
#define IO_TYPE_CONTROLLER                      2
#define IO_TYPE_DEVICE                          3
#define IO_TYPE_DRIVER                          4
#define IO_TYPE_FILE                            5
#define IO_TYPE_IRP                             6
#define IO_TYPE_DEVICE_OBJECT_EXTENSION         13

struct irp;
struct dev_obj_ext;
struct driver_object;

struct device_object {
        CSHORT type;
        USHORT size;
        LONG ref_count;
        struct driver_object *drv_obj;
        struct device_object *next;
        struct device_object *attached;
        struct irp *current_irp;
        void *io_timer;
        ULONG flags;
        ULONG characteristics;
        void *vpb;
        void *dev_ext;
        CCHAR stack_count;
        union {
                struct nt_list queue_list;
                struct wait_context_block wcb;
        } queue;
        ULONG align_req;
        struct kdevice_queue dev_queue;
        struct kdpc dpc;
        ULONG active_threads;
        void *security_desc;
        struct nt_event lock;
        USHORT sector_size;
        USHORT spare1;
        struct dev_obj_ext *dev_obj_ext;
        void *reserved;
};

struct dev_obj_ext {
        CSHORT type;
        CSHORT size;
        struct device_object *dev_obj;
        struct device_object *attached_to;
};

struct io_status_block {
        union {
                NTSTATUS status;
                void *pointer;
        };
        ULONG_PTR info;
};


#define DEVICE_TYPE ULONG

struct driver_extension;

typedef NTSTATUS driver_dispatch_t(struct device_object *dev_obj,
                                   struct irp *irp) wstdcall;

struct driver_object {
        CSHORT type;
        CSHORT size;
        struct device_object *dev_obj;
        ULONG flags;
        void *start;
        ULONG driver_size;
        void *section;
        struct driver_extension *drv_ext;
        struct unicode_string name;
        struct unicode_string *hardware_database;
        void *fast_io_dispatch;
        void *init;
        void *start_io;
        void (*unload)(struct driver_object *driver) wstdcall;
        driver_dispatch_t *major_func[IRP_MJ_MAXIMUM_FUNCTION + 1];
};

struct driver_extension {
        struct driver_object *drv_obj;
        NTSTATUS (*add_device)(struct driver_object *drv_obj,
                               struct device_object *dev_obj);
        ULONG count;
        struct unicode_string service_key_name;
        struct nt_list custom_ext;
};

struct custom_ext {
        struct nt_list list;
        void *client_id;
};

struct wrap_bin_file;

struct file_object {
        CSHORT type;
        CSHORT size;
        struct device_object *dev_obj;
        void *volume_parameter_block;
        void *fs_context;
        void *fs_context2;
        void *section_object_pointer;
        void *private_cache_map;
        NTSTATUS final_status;
        union {
                struct file_object *related_file_object;
                struct wrap_bin_file *wrap_bin_file;
        };
        BOOLEAN lock_operation;
        BOOLEAN delete_pending;
        BOOLEAN read_access;
        BOOLEAN write_access;
        BOOLEAN delete_access;
        BOOLEAN shared_read;
        BOOLEAN shared_write;
        BOOLEAN shared_delete;
        ULONG flags;
        struct unicode_string _name_;
        LARGE_INTEGER current_byte_offset;
        ULONG waiters;
        ULONG busy;
        void *last_lock;
        struct nt_event lock;
        struct nt_event event;
        void *completion_context;
};

#define POINTER_ALIGN

#define CACHE_ALIGN __attribute__((aligned(128)))

enum system_power_state {
        PowerSystemUnspecified = 0,
        PowerSystemWorking, PowerSystemSleeping1, PowerSystemSleeping2,
        PowerSystemSleeping3, PowerSystemHibernate, PowerSystemShutdown,
        PowerSystemMaximum,
};

enum device_power_state {
        PowerDeviceUnspecified = 0,
        PowerDeviceD0, PowerDeviceD1, PowerDeviceD2, PowerDeviceD3,
        PowerDeviceMaximum,
};

union power_state {
        enum system_power_state system_state;
        enum device_power_state device_state;
};

enum power_state_type {
        SystemPowerState = 0, DevicePowerState,
};

enum power_action {
        PowerActionNone = 0,
        PowerActionReserved, PowerActionSleep, PowerActionHibernate,
        PowerActionShutdown, PowerActionShutdownReset, PowerActionShutdownOff,
        PowerActionWarmEject,
};

typedef struct guid {
        ULONG data1;
        USHORT data2;
        USHORT data3;
        UCHAR data4[8];
} GUID, *PGUID, *LPGUID;

struct nt_interface {
        USHORT size;
        USHORT version;
        void *context;
        void (*reference)(void *context) wstdcall;
        void (*dereference)(void *context) wstdcall;
};

enum interface_type {
        InterfaceTypeUndefined = -1, Internal, Isa, Eisa, MicroChannel,
        TurboChannel, PCIBus, VMEBus, NuBus, PCMCIABus, CBus, MPIBus,
        MPSABus, ProcessorInternal, InternalPowerBus, PNPISABus,
        PNPBus, MaximumInterfaceType,
};

#define CmResourceTypeNull              0
#define CmResourceTypePort              1
#define CmResourceTypeInterrupt         2
#define CmResourceTypeMemory            3
#define CmResourceTypeDma               4
#define CmResourceTypeDeviceSpecific    5
#define CmResourceTypeBusNumber         6
#define CmResourceTypeMaximum           7

#define CmResourceTypeNonArbitrated     128
#define CmResourceTypeConfigData        128
#define CmResourceTypeDevicePrivate     129
#define CmResourceTypePcCardConfig      130
#define CmResourceTypeMfCardConfig      131

enum cm_share_disposition {
        CmResourceShareUndetermined = 0, CmResourceShareDeviceExclusive,
        CmResourceShareDriverExclusive, CmResourceShareShared
};

#define CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE   0
#define CM_RESOURCE_INTERRUPT_LATCHED           1
#define CM_RESOURCE_MEMORY_READ_WRITE           0x0000
#define CM_RESOURCE_MEMORY_READ_ONLY            0x0001
#define CM_RESOURCE_MEMORY_WRITE_ONLY           0x0002
#define CM_RESOURCE_MEMORY_PREFETCHABLE         0x0004

#define CM_RESOURCE_MEMORY_COMBINEDWRITE        0x0008
#define CM_RESOURCE_MEMORY_24                   0x0010
#define CM_RESOURCE_MEMORY_CACHEABLE            0x0020

#define CM_RESOURCE_PORT_MEMORY                 0x0000
#define CM_RESOURCE_PORT_IO                     0x0001
#define CM_RESOURCE_PORT_10_BIT_DECODE          0x0004
#define CM_RESOURCE_PORT_12_BIT_DECODE          0x0008
#define CM_RESOURCE_PORT_16_BIT_DECODE          0x0010
#define CM_RESOURCE_PORT_POSITIVE_DECODE        0x0020
#define CM_RESOURCE_PORT_PASSIVE_DECODE         0x0040
#define CM_RESOURCE_PORT_WINDOW_DECODE          0x0080

#define CM_RESOURCE_DMA_8                       0x0000
#define CM_RESOURCE_DMA_16                      0x0001
#define CM_RESOURCE_DMA_32                      0x0002
#define CM_RESOURCE_DMA_8_AND_16                0x0004
#define CM_RESOURCE_DMA_BUS_MASTER              0x0008
#define CM_RESOURCE_DMA_TYPE_A                  0x0010
#define CM_RESOURCE_DMA_TYPE_B                  0x0020
#define CM_RESOURCE_DMA_TYPE_F                  0x0040

#define MAX_RESOURCES 20

#pragma pack(push,4)
struct cm_partial_resource_descriptor {
        UCHAR type;
        UCHAR share;
        USHORT flags;
        union {
                struct {
                        PHYSICAL_ADDRESS start;
                        ULONG length;
                } generic;
                struct {
                        PHYSICAL_ADDRESS start;
                        ULONG length;
                } port;
                struct {
                        ULONG level;
                        ULONG vector;
                        KAFFINITY affinity;
                } interrupt;
                struct {
                        PHYSICAL_ADDRESS start;
                        ULONG length;
                } memory;
                struct {
                        ULONG channel;
                        ULONG port;
                        ULONG reserved1;
                } dma;
                struct {
                        ULONG data[3];
                } device_private;
                struct {
                        ULONG start;
                        ULONG length;
                        ULONG reserved;
                } bus_number;
                struct {
                        ULONG data_size;
                        ULONG reserved1;
                        ULONG reserved2;
                } device_specific_data;
        } u;
};
#pragma pack(pop)

struct cm_partial_resource_list {
        USHORT version;
        USHORT revision;
        ULONG count;
        struct cm_partial_resource_descriptor partial_descriptors[1];
};

struct cm_full_resource_descriptor {
        enum interface_type interface_type;
        ULONG bus_number;
        struct cm_partial_resource_list partial_resource_list;
};

struct cm_resource_list {
        ULONG count;
        struct cm_full_resource_descriptor list[1];
};

enum file_info_class {
        FileDirectoryInformation = 1,
        FileBasicInformation = 4,
        FileStandardInformation = 5,
        FileNameInformation = 9,
        FilePositionInformation = 14,
        FileAlignmentInformation = 17,
        FileNetworkOpenInformation = 34,
        FileAttributeTagInformation = 35,
        FileMaximumInformation = 41,
};

enum fs_info_class {
        FileFsVolumeInformation = 1,
        /* ... */
        FileFsMaximumInformation = 9,
};

enum device_relation_type {
        BusRelations, EjectionRelations, PowerRelations, RemovalRelations,
        TargetDeviceRelation, SingleBusRelations,
};

enum bus_query_id_type {
        BusQueryDeviceID = 0, BusQueryHardwareIDs = 1,
        BusQueryCompatibleIDs = 2, BusQueryInstanceID = 3,
        BusQueryDeviceSerialNumber = 4,
};

enum device_text_type {
        DeviceTextDescription = 0, DeviceTextLocationInformation = 1,
};

enum device_usage_notification_type {
        DeviceUsageTypeUndefined, DeviceUsageTypePaging,
        DeviceUsageTypeHibernation, DevbiceUsageTypeDumpFile,
};

#define METHOD_BUFFERED         0
#define METHOD_IN_DIRECT        1
#define METHOD_OUT_DIRECT       2
#define METHOD_NEITHER          3

#define CTL_CODE(dev_type, func, method, access)                        \
        (((dev_type) << 16) | ((access) << 14) | ((func) << 2) | (method))

#define IO_METHOD_FROM_CTL_CODE(code) (code & 0x3)

struct io_stack_location {
        UCHAR major_fn;
        UCHAR minor_fn;
        UCHAR flags;
        UCHAR control;
        union {
                struct {
                        void *security_context;
                        ULONG options;
                        USHORT POINTER_ALIGN file_attributes;
                        USHORT share_access;
                        ULONG POINTER_ALIGN ea_length;
                } create;
                struct {
                        ULONG length;
                        ULONG POINTER_ALIGN key;
                        LARGE_INTEGER byte_offset;
                } read;
                struct {
                        ULONG length;
                        ULONG POINTER_ALIGN key;
                        LARGE_INTEGER byte_offset;
                } write;
                struct {
                        ULONG length;
                        enum file_info_class POINTER_ALIGN file_info_class;
                } query_file;
                struct {
                        ULONG length;
                        enum file_info_class POINTER_ALIGN file_info_class;
                        struct file_object *file_object;
                        union {
                                struct {
                                        BOOLEAN replace_if_exists;
                                        BOOLEAN advance_only;
                                };
                                ULONG cluster_count;
                                void *delete_handle;
                        };
                } set_file;
                struct {
                        ULONG length;
                        enum fs_info_class POINTER_ALIGN fs_info_class;
                } query_volume;
                struct {
                        ULONG output_buf_len;
                        ULONG POINTER_ALIGN input_buf_len;
                        ULONG POINTER_ALIGN code;
                        void *type3_input_buf;
                } dev_ioctl;
                struct {
                        SECURITY_INFORMATION security_info;
                        ULONG POINTER_ALIGN length;
                } query_security;
                struct {
                        SECURITY_INFORMATION security_info;
                        void *security_descriptor;
                } set_security;
                struct {
                        void *vpb;
                        struct device_object *device_object;
                } mount_volume;
                struct {
                        void *vpb;
                        struct device_object *device_object;
                } verify_volume;
                struct {
                        void *srb;
                } scsi;
                struct {
                        enum device_relation_type type;
                } query_device_relations;
                struct {
                        const struct guid *type;
                        USHORT size;
                        USHORT version;
                        struct nt_interface *intf;
                        void *intf_data;
                } query_intf;
                struct {
                        void *capabilities;
                } device_capabilities;
                struct {
                        void *io_resource_requirement_list;
                } filter_resource_requirements;
                struct {
                        ULONG which_space;
                        void *buffer;
                        ULONG offset;
                        ULONG POINTER_ALIGN length;
                } read_write_config;
                struct {
                        BOOLEAN lock;
                } set_lock;
                struct {
                        enum bus_query_id_type id_type;
                } query_id;
                struct {
                        enum device_text_type device_text_type;
                        ULONG POINTER_ALIGN locale_id;
                } query_device_text;
                struct {
                        BOOLEAN in_path;
                        BOOLEAN reserved[3];
                        enum device_usage_notification_type POINTER_ALIGN type;
                } usage_notification;
                struct {
                        enum system_power_state power_state;
                } wait_wake;
                struct {
                        void *power_sequence;
                } power_sequence;
                struct {
                        ULONG sys_context;
                        enum power_state_type POINTER_ALIGN type;
                        union power_state POINTER_ALIGN state;
                        enum power_action POINTER_ALIGN shutdown_type;
                } power;
                struct {
                        struct cm_resource_list *allocated_resources;
                        struct cm_resource_list *allocated_resources_translated;
                } start_device;
                struct {
                        ULONG_PTR provider_id;
                        void *data_path;
                        ULONG buf_len;
                        void *buf;
                } wmi;
                struct {
                        void *arg1;
                        void *arg2;
                        void *arg3;
                        void *arg4;
                } others;
        } params;
        struct device_object *dev_obj;
        struct file_object *file_obj;
        NTSTATUS (*completion_routine)(struct device_object *,
                                       struct irp *, void *) wstdcall;
        void *context;
};

struct kapc {
        CSHORT type;
        CSHORT size;
        ULONG spare0;
        struct nt_thread *thread;
        struct nt_list list;
        void *kernele_routine;
        void *rundown_routine;
        void *normal_routine;
        void *normal_context;
        void *sys_arg1;
        void *sys_arg2;
        CCHAR apc_state_index;
        KPROCESSOR_MODE apc_mode;
        BOOLEAN inserted;
};

#define IRP_NOCACHE                     0x00000001
#define IRP_SYNCHRONOUS_API             0x00000004
#define IRP_ASSOCIATED_IRP              0x00000008

enum urb_state {
        URB_INVALID = 1, URB_ALLOCATED, URB_SUBMITTED,
        URB_COMPLETED, URB_FREE, URB_SUSPEND, URB_INT_UNLINKED };

struct wrap_urb {
        struct nt_list list;
        enum urb_state state;
        struct nt_list complete_list;
        unsigned int flags;
        struct urb *urb;
        struct irp *irp;
#ifdef USB_DEBUG
        unsigned int id;
#endif
};

struct irp {
        SHORT type;
        USHORT size;
        struct mdl *mdl;
        ULONG flags;
        union {
                struct irp *master_irp;
                LONG irp_count;
                void *system_buffer;
        } associated_irp;
        struct nt_list thread_list;
        struct io_status_block io_status;
        KPROCESSOR_MODE requestor_mode;
        BOOLEAN pending_returned;
        CHAR stack_count;
        CHAR current_location;
        BOOLEAN cancel;
        KIRQL cancel_irql;
        CCHAR apc_env;
        UCHAR alloc_flags;
        struct io_status_block *user_status;
        struct nt_event *user_event;
        union {
                struct {
                        void *user_apc_routine;
                        void *user_apc_context;
                } async_params;
                LARGE_INTEGER alloc_size;
        } overlay;
        void (*cancel_routine)(struct device_object *, struct irp *) wstdcall;
        void *user_buf;
        union {
                struct {
                        union {
                                struct kdevice_queue_entry dev_q_entry;
                                struct {
                                        void *driver_context[4];
                                };
                        };
                        void *thread;
                        char *aux_buf;
                        struct {
                                struct nt_list list;
                                union {
                                        struct io_stack_location *csl;
                                        ULONG packet_type;
                                };
                        };
                        struct file_object *file_object;
                } overlay;
                union {
                        struct kapc apc;
                        /* space for apc is used for ndiswrapper
                         * specific fields */
                        struct {
                                struct wrap_urb *wrap_urb;
                                struct wrap_device *wrap_device;
                        };
                };
                void *completion_key;
        } tail;
};

#define IoSizeOfIrp(stack_count)                                        \
        ((USHORT)(sizeof(struct irp) +                                  \
                  ((stack_count) * sizeof(struct io_stack_location))))
#define IoGetCurrentIrpStackLocation(irp)       \
        (irp)->tail.overlay.csl
#define IoGetNextIrpStackLocation(irp)          \
        (IoGetCurrentIrpStackLocation(irp) - 1)
#define IoGetPreviousIrpStackLocation(irp)      \
        (IoGetCurrentIrpStackLocation(irp) + 1)

#define IoSetNextIrpStackLocation(irp)                          \
do {                                                            \
        KIRQL _irql_;                                           \
        IoAcquireCancelSpinLock(&_irql_);                       \
        (irp)->current_location--;                              \
        IoGetCurrentIrpStackLocation(irp)--;                    \
        IoReleaseCancelSpinLock(_irql_);                        \
} while (0)

#define IoSkipCurrentIrpStackLocation(irp)                      \
do {                                                            \
        KIRQL _irql_;                                           \
        IoAcquireCancelSpinLock(&_irql_);                       \
        (irp)->current_location++;                              \
        IoGetCurrentIrpStackLocation(irp)++;                    \
        IoReleaseCancelSpinLock(_irql_);                        \
} while (0)

static inline void
IoCopyCurrentIrpStackLocationToNext(struct irp *irp)
{
        struct io_stack_location *next;
        next = IoGetNextIrpStackLocation(irp);
        memcpy(next, IoGetCurrentIrpStackLocation(irp),
               offsetof(struct io_stack_location, completion_routine));
        next->control = 0;
}

static inline void
IoSetCompletionRoutine(struct irp *irp, void *routine, void *context,
                       BOOLEAN success, BOOLEAN error, BOOLEAN cancel)
{
        struct io_stack_location *irp_sl = IoGetNextIrpStackLocation(irp);
        irp_sl->completion_routine = routine;
        irp_sl->context = context;
        irp_sl->control = 0;
        if (success)
                irp_sl->control |= SL_INVOKE_ON_SUCCESS;
        if (error)
                irp_sl->control |= SL_INVOKE_ON_ERROR;
        if (cancel)
                irp_sl->control |= SL_INVOKE_ON_CANCEL;
}

#define IoMarkIrpPending(irp)                                           \
        (IoGetCurrentIrpStackLocation((irp))->control |= SL_PENDING_RETURNED)
#define IoUnmarkIrpPending(irp)                                         \
        (IoGetCurrentIrpStackLocation((irp))->control &= ~SL_PENDING_RETURNED)

#define IRP_SL(irp, n) (((struct io_stack_location *)((irp) + 1)) + (n))
#define IRP_DRIVER_CONTEXT(irp) (irp)->tail.overlay.driver_context
#define IoIrpThread(irp) ((irp)->tail.overlay.thread)

#define IRP_URB(irp)                                                    \
        (union nt_urb *)(IoGetCurrentIrpStackLocation(irp)->params.others.arg1)

#define IRP_WRAP_DEVICE(irp) (irp)->tail.wrap_device
#define IRP_WRAP_URB(irp) (irp)->tail.wrap_urb

struct wmi_guid_reg_info {
        struct guid *guid;
        ULONG instance_count;
        ULONG flags;
};

struct wmilib_context {
        ULONG guid_count;
        struct wmi_guid_reg_info *guid_list;
        void *query_wmi_reg_info;
        void *query_wmi_data_block;
        void *set_wmi_data_block;
        void *set_wmi_data_item;
        void *execute_wmi_method;
        void *wmi_function_control;
};

enum key_value_information_class {
        KeyValueBasicInformation, KeyValueFullInformation,
        KeyValuePartialInformation, KeyValueFullInformationAlign64,
        KeyValuePartialInformationAlign64
};

struct file_name_info {
        ULONG length;
        wchar_t *name;
};

struct file_std_info {
        LARGE_INTEGER alloc_size;
        LARGE_INTEGER eof;
        ULONG num_links;
        BOOLEAN delete_pending;
        BOOLEAN dir;
};

enum nt_obj_type {
        NT_OBJ_EVENT = 10, NT_OBJ_MUTEX, NT_OBJ_THREAD, NT_OBJ_TIMER,
        NT_OBJ_SEMAPHORE,
};

enum common_object_type {
        OBJECT_TYPE_NONE, OBJECT_TYPE_DEVICE, OBJECT_TYPE_DRIVER,
        OBJECT_TYPE_NT_THREAD, OBJECT_TYPE_FILE, OBJECT_TYPE_CALLBACK,
};

struct common_object_header {
        struct nt_list list;
        enum common_object_type type;
        UINT size;
        UINT ref_count;
        BOOLEAN close_in_process;
        BOOLEAN permanent;
        struct unicode_string name;
};

#define OBJECT_TO_HEADER(object)                                        \
        (struct common_object_header *)((void *)(object) -              \
                                        sizeof(struct common_object_header))
#define OBJECT_SIZE(size)                               \
        ((size) + sizeof(struct common_object_header))
#define HEADER_TO_OBJECT(hdr)                                   \
        ((void *)(hdr) + sizeof(struct common_object_header))
#define HANDLE_TO_OBJECT(handle) HEADER_TO_OBJECT(handle)
#define HANDLE_TO_HEADER(handle) (handle)

enum work_queue_type {
        CriticalWorkQueue, DelayedWorkQueue, HyperCriticalWorkQueue,
        MaximumWorkQueue
};

typedef void (*NTOS_WORK_FUNC)(void *arg1, void *arg2) wstdcall;

struct io_workitem {
        enum work_queue_type type;
        struct device_object *dev_obj;
        NTOS_WORK_FUNC worker_routine;
        void *context;
};

struct io_workitem_entry {
        struct nt_list list;
        struct io_workitem *io_workitem;
};

enum mm_page_priority {
        LowPagePriority, NormalPagePriority = 16, HighPagePriority = 32
};

enum kinterrupt_mode {
        LevelSensitive, Latched
};

enum ntos_wait_reason {
        Executive, FreePage, PageIn, PoolAllocation, DelayExecution,
        Suspended, UserRequest, WrExecutive, WrFreePage, WrPageIn,
        WrPoolAllocation, WrDelayExecution, WrSuspended, WrUserRequest,
        WrEventPair, WrQueue, WrLpcReceive, WrLpcReply, WrVirtualMemory,
        WrPageOut, WrRendezvous, Spare2, Spare3, Spare4, Spare5, Spare6,
        WrKernel, MaximumWaitReason
};

typedef enum ntos_wait_reason KWAIT_REASON;

typedef void *LOOKASIDE_ALLOC_FUNC(enum pool_type pool_type,
                                   SIZE_T size, ULONG tag) wstdcall;
typedef void LOOKASIDE_FREE_FUNC(void *) wstdcall;

struct npaged_lookaside_list {
        nt_slist_header head;
        USHORT depth;
        USHORT maxdepth;
        ULONG totalallocs;
        union {
                ULONG allocmisses;
                ULONG allochits;
        } u1;
        ULONG totalfrees;
        union {
                ULONG freemisses;
                ULONG freehits;
        } u2;
        enum pool_type pool_type;
        ULONG tag;
        ULONG size;
        LOOKASIDE_ALLOC_FUNC *alloc_func;
        LOOKASIDE_FREE_FUNC *free_func;
        struct nt_list list;
        ULONG lasttotallocs;
        union {
                ULONG lastallocmisses;
                ULONG lastallochits;
        } u3;
        ULONG pad[2];
}
;

enum device_registry_property {
        DevicePropertyDeviceDescription, DevicePropertyHardwareID,
        DevicePropertyCompatibleIDs, DevicePropertyBootConfiguration,
        DevicePropertyBootConfigurationTranslated,
        DevicePropertyClassName, DevicePropertyClassGuid,
        DevicePropertyDriverKeyName, DevicePropertyManufacturer,
        DevicePropertyFriendlyName, DevicePropertyLocationInformation,
        DevicePropertyPhysicalDeviceObjectName, DevicePropertyBusTypeGuid,
        DevicePropertyLegacyBusType, DevicePropertyBusNumber,
        DevicePropertyEnumeratorName, DevicePropertyAddress,
        DevicePropertyUINumber, DevicePropertyInstallState,
        DevicePropertyRemovalPolicy
};

enum trace_information_class {
        TraceIdClass, TraceHandleClass, TraceEnableFlagsClass,
        TraceEnableLevelClass, GlobalLoggerHandleClass, EventLoggerHandleClass,
        AllLoggerHandlesClass, TraceHandleByNameClass
};

struct kinterrupt;
typedef BOOLEAN (*PKSERVICE_ROUTINE)(struct kinterrupt *interrupt,
                                     void *context) wstdcall;
typedef BOOLEAN (*PKSYNCHRONIZE_ROUTINE)(void *context) wstdcall;

struct kinterrupt {
        ULONG vector;
        KAFFINITY cpu_mask;
        NT_SPIN_LOCK lock;
        NT_SPIN_LOCK *actual_lock;
        BOOLEAN shared;
        BOOLEAN save_fp;
        union {
                CHAR processor_number;
#ifdef CONFIG_DEBUG_SHIRQ
                CHAR enabled;
#endif
        } u;
        PKSERVICE_ROUTINE isr;
        void *isr_ctx;
        struct nt_list list;
        KIRQL irql;
        KIRQL synch_irql;
        enum kinterrupt_mode mode;
};

struct time_fields {
        CSHORT year;
        CSHORT month;
        CSHORT day;
        CSHORT hour;
        CSHORT minute;
        CSHORT second;
        CSHORT milliseconds;
        CSHORT weekday;
};

struct object_attributes {
        ULONG length;
        void *root_dir;
        struct unicode_string *name;
        ULONG attributes;
        void *security_descr;
        void *security_qos;
};

typedef void (*PFLS_CALLBACK_FUNCTION)(PVOID lpFlsData) wstdcall;

typedef void (*PCALLBACK_FUNCTION)(void *context, void *arg1,
                                   void *arg2) wstdcall;

struct callback_object;
struct callback_func {
        PCALLBACK_FUNCTION func;
        void *context;
        struct nt_list list;
        struct callback_object *object;
};

struct callback_object {
        NT_SPIN_LOCK lock;
        struct nt_list list;
        struct nt_list callback_funcs;
        BOOLEAN allow_multiple_callbacks;
        struct object_attributes *attributes;
};

enum section_inherit {
        ViewShare = 1, ViewUnmap = 2
};

struct ksystem_time {
        ULONG low_part;
        LONG high1_time;
        LONG high2_time;
};

enum nt_product_type {
        nt_product_win_nt = 1, nt_product_lan_man_nt, nt_product_server
};

enum alt_arch_type {
        arch_type_standard, arch_type_nex98x86, end_alternatives
};

#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define MAXIMUM_SUPPORTED_EXTENSION  512
#define SIZE_OF_80387_REGISTERS      80

typedef enum
{
         ExceptionContinueExecution = 0,
         ExceptionContinueSearch = 1,
         ExceptionNestedException = 2,
         ExceptionCollidedUnwind = 3
} EXCEPTION_DISPOSITION;

typedef struct _EXCEPTION_RECORD {
  DWORD                    ExceptionCode;
  DWORD                    ExceptionFlags;
  struct _EXCEPTION_RECORD  *ExceptionRecord;
  PVOID                    ExceptionAddress;
  DWORD                    NumberParameters;
  ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

typedef struct _FLOATING_SAVE_AREA {
  DWORD   ControlWord;
  DWORD   StatusWord;
  DWORD   TagWord;
  DWORD   ErrorOffset;
  DWORD   ErrorSelector;
  DWORD   DataOffset;
  DWORD   DataSelector;
  BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
  DWORD   Cr0NpxState;
} FLOATING_SAVE_AREA;

typedef struct _CONTEXT {
  DWORD ContextFlags;

  DWORD   Dr0;
  DWORD   Dr1;
  DWORD   Dr2;
  DWORD   Dr3;
  DWORD   Dr6;
  DWORD   Dr7;

  FLOATING_SAVE_AREA FloatSave;

  DWORD   SegGs;
  DWORD   SegFs;
  DWORD   SegEs;
  DWORD   SegDs;

  DWORD   Edi;
  DWORD   Esi;
  DWORD   Ebx;
  DWORD   Edx;
  DWORD   Ecx;
  DWORD   Eax;

  DWORD   Ebp;
  DWORD   Eip;
  DWORD   SegCs;
  DWORD   EFlags;
  DWORD   Esp;
  DWORD   SegSs;

  BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT;

struct _EXCEPTION_FRAME;

typedef EXCEPTION_DISPOSITION (*PEXCEPTION_HANDLER)(
    struct _EXCEPTION_RECORD *ExceptionRecord,
    struct _EXCEPTION_FRAME *EstablisherFrame,
    struct _CONTEXT *ContextRecord,
    struct _EXCEPTION_FRAME **DispatcherContext);

typedef struct _EXCEPTION_FRAME {
  struct _EXCEPTION_FRAME *prev;
  PEXCEPTION_HANDLER handler;
} EXCEPTION_FRAME, *PEXCEPTION_FRAME;

typedef struct _RTL_BITMAP {
    ULONG  SizeOfBitMap;
    LPBYTE Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

typedef const RTL_BITMAP *PCRTL_BITMAP;

typedef struct _RTL_BITMAP_RUN {
    ULONG StartingIndex;
    ULONG NumberOfBits;
} RTL_BITMAP_RUN, *PRTL_BITMAP_RUN;

typedef const RTL_BITMAP_RUN *PCRTL_BITMAP_RUN;

typedef struct _KUSER_SHARED_DATA {
        ULONG tick_count;
        ULONG tick_count_multiplier;
        volatile struct ksystem_time interrupt_time;
        volatile struct ksystem_time system_time;
        volatile struct ksystem_time time_zone_bias;
        USHORT image_number_low;
        USHORT image_number_high;
        wchar_t nt_system_root[260];
        ULONG max_stack_trace_depth;
        ULONG crypto_exponent;
        ULONG time_zone_id;
        ULONG large_page_min;
        ULONG reserved2[7];
        enum nt_product_type nt_product_type;
        BOOLEAN product_type_is_valid;
        ULONG nt_major_version;
        ULONG nt_minor_version;
        BOOLEAN processor_features[PROCESSOR_FEATURE_MAX];
        ULONG reserved1;
        ULONG reserved3;
        volatile LONG time_slip;
        enum alt_arch_type alt_arch_type;
        LARGE_INTEGER system_expiration_date;
        ULONG suite_mask;
        BOOLEAN kdbg_enabled;
        volatile ULONG active_console;
        volatile ULONG dismount_count;
        ULONG com_plus_package;
        ULONG last_system_rite_event_tick_count;
        ULONG num_phys_pages;
        BOOLEAN safe_boot_mode;
        ULONG trace_log;
        ULONGLONG fill0;
        ULONGLONG sys_call[4];
        union {
                volatile struct ksystem_time tick_count;
                volatile ULONG64 tick_count_quad;
        } tick;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

#define REG_NONE                        (0)
#define REG_SZ                          (1)
#define REG_EXPAND_SZ                   (2)
#define REG_BINARY                      (3)
#define REG_DWORD                       (4)

#define RTL_REGISTRY_ABSOLUTE           0
#define RTL_REGISTRY_SERVICES           1
#define RTL_REGISTRY_CONTROL            2
#define RTL_REGISTRY_WINDOWS_NT         3
#define RTL_REGISTRY_DEVICEMAP          4
#define RTL_REGISTRY_USER               5
#define RTL_REGISTRY_MAXIMUM            6
#define RTL_REGISTRY_HANDLE             0x40000000
#define RTL_REGISTRY_OPTIONAL           0x80000000

#define RTL_QUERY_REGISTRY_SUBKEY       0x00000001
#define RTL_QUERY_REGISTRY_TOPKEY       0x00000002
#define RTL_QUERY_REGISTRY_REQUIRED     0x00000004
#define RTL_QUERY_REGISTRY_NOVALUE      0x00000008
#define RTL_QUERY_REGISTRY_NOEXPAND     0x00000010
#define RTL_QUERY_REGISTRY_DIRECT       0x00000020
#define RTL_QUERY_REGISTRY_DELETE       0x00000040

typedef NTSTATUS (*PRTL_QUERY_REGISTRY_ROUTINE)(wchar_t *name, ULONG type,
                                                void *data, ULONG length,
                                                void *context,
                                                void *entry) wstdcall;

struct rtl_query_registry_table {
        PRTL_QUERY_REGISTRY_ROUTINE query_func;
        ULONG flags;
        wchar_t *name;
        void *context;
        ULONG def_type;
        void *def_data;
        ULONG def_length;
};

struct io_remove_lock {
        BOOLEAN removed;
        BOOLEAN reserved[3];
        LONG io_count;
        struct nt_event remove_event;
};

struct io_error_log_packet {
        UCHAR major_fn_code;
        UCHAR retry_count;
        USHORT dump_data_size;
        USHORT nr_of_strings;
        USHORT string_offset;
        USHORT event_category;
        NTSTATUS error_code;
        ULONG unique_error_value;
        NTSTATUS final_status;
        ULONG sequence_number;
        ULONG io_control_code;
        LARGE_INTEGER device_offset;
        ULONG dump_data[1];
};

/* some of the functions below are slightly different from DDK's
 * implementation; e.g., Insert functions return appropriate
 * pointer */

/* instead of using Linux's lists, we implement list manipulation
 * functions because nt_list is used by drivers and we don't want to
 * worry about Linux's list being different from nt_list (right now
 * they are same, but in future they could be different) */

static inline void InitializeListHead(struct nt_list *head)
{
        head->next = head->prev = head;
}

static inline BOOLEAN IsListEmpty(struct nt_list *head)
{
        if (head == head->next)
                return TRUE;
        else
                return FALSE;
}

static inline void RemoveEntryList(struct nt_list *entry)
{
        entry->prev->next = entry->next;
        entry->next->prev = entry->prev;
}

static inline struct nt_list *RemoveHeadList(struct nt_list *head)
{
        struct nt_list *entry;

        entry = head->next;
        if (entry == head)
                return NULL;
        else {
                RemoveEntryList(entry);
                return entry;
        }
}

static inline struct nt_list *RemoveTailList(struct nt_list *head)
{
        struct nt_list *entry;

        entry = head->prev;
        if (entry == head)
                return NULL;
        else {
                RemoveEntryList(entry);
                return entry;
        }
}

static inline void InsertListEntry(struct nt_list *entry, struct nt_list *prev,
                                   struct nt_list *next)
{
        next->prev = entry;
        entry->next = next;
        entry->prev = prev;
        prev->next = entry;
}

static inline struct nt_list *InsertHeadList(struct nt_list *head,
                                             struct nt_list *entry)
{
        struct nt_list *ret;

        if (IsListEmpty(head))
                ret = NULL;
        else
                ret = head->next;

        InsertListEntry(entry, head, head->next);
        return ret;
}

static inline struct nt_list *InsertTailList(struct nt_list *head,
                                             struct nt_list *entry)
{
        struct nt_list *ret;

        if (IsListEmpty(head))
                ret = NULL;
        else
                ret = head->prev;

        InsertListEntry(entry, head->prev, head);
        return ret;
}

#define nt_list_for_each(pos, head)                                     \
        for (pos = (head)->next; pos != (head); pos = pos->next)

#define nt_list_for_each_entry(pos, head, member)                       \
        for (pos = container_of((head)->next, typeof(*pos), member);    \
             &pos->member != (head);                                    \
             pos = container_of(pos->member.next, typeof(*pos), member))

#define nt_list_for_each_safe(pos, n, head)                     \
        for (pos = (head)->next, n = pos->next; pos != (head);  \
             pos = n, n = pos->next)

/* device object flags */
#define DO_VERIFY_VOLUME                0x00000002
#define DO_BUFFERED_IO                  0x00000004
#define DO_EXCLUSIVE                    0x00000008
#define DO_DIRECT_IO                    0x00000010
#define DO_MAP_IO_BUFFER                0x00000020
#define DO_DEVICE_HAS_NAME              0x00000040
#define DO_DEVICE_INITIALIZING          0x00000080
#define DO_SYSTEM_BOOT_PARTITION        0x00000100
#define DO_LONG_TERM_REQUESTS           0x00000200
#define DO_NEVER_LAST_DEVICE            0x00000400
#define DO_SHUTDOWN_REGISTERED          0x00000800
#define DO_BUS_ENUMERATED_DEVICE        0x00001000
#define DO_POWER_PAGABLE                0x00002000
#define DO_POWER_INRUSH                 0x00004000
#define DO_LOW_PRIORITY_FILESYSTEM      0x00010000

/* Various supported device types (used with IoCreateDevice()) */

#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_INPORT_PORT         0x0000000A
#define FILE_DEVICE_KEYBOARD            0x0000000B
#define FILE_DEVICE_MAILSLOT            0x0000000C
#define FILE_DEVICE_MIDI_IN             0x0000000D
#define FILE_DEVICE_MIDI_OUT            0x0000000E
#define FILE_DEVICE_MOUSE               0x0000000F
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001A
#define FILE_DEVICE_SERIAL_PORT         0x0000001B
#define FILE_DEVICE_SCREEN              0x0000001C
#define FILE_DEVICE_SOUND               0x0000001D
#define FILE_DEVICE_STREAMS             0x0000001E
#define FILE_DEVICE_TAPE                0x0000001F
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026
#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BUS_EXTENDER        0x0000002A
#define FILE_DEVICE_MODEM               0x0000002B
#define FILE_DEVICE_VDM                 0x0000002C
#define FILE_DEVICE_MASS_STORAGE        0x0000002D
#define FILE_DEVICE_SMB                 0x0000002E
#define FILE_DEVICE_KS                  0x0000002F
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_KSEC                0x00000039
#define FILE_DEVICE_FIPS                0x0000003A

/* Device characteristics */

#define FILE_REMOVABLE_MEDIA            0x00000001
#define FILE_READ_ONLY_DEVICE           0x00000002
#define FILE_FLOPPY_DISKETTE            0x00000004
#define FILE_WRITE_ONCE_MEDIA           0x00000008
#define FILE_REMOTE_DEVICE              0x00000010
#define FILE_DEVICE_IS_MOUNTED          0x00000020
#define FILE_VIRTUAL_VOLUME             0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME  0x00000080
#define FILE_DEVICE_SECURE_OPEN         0x00000100

#define FILE_READ_DATA                  0x0001
#define FILE_WRITE_DATA                 0x0002

#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005

#endif /* WINNT_TYPES_H */
