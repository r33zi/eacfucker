#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <ntimage.h>

#ifndef WORD_DEFINED
#define WORD_DEFINED
typedef unsigned short WORD;
#endif

#ifndef DWORD_DEFINED
#define DWORD_DEFINED
typedef unsigned long DWORD;
#endif

#ifndef BYTE_DEFINED
#define BYTE_DEFINED
typedef unsigned char BYTE;
#endif

#ifndef LONG_DEFINED
#define LONG_DEFINED
typedef long LONG;
#endif

#ifndef ULONG_DEFINED
#define ULONG_DEFINED
typedef unsigned long ULONG;
#endif

#ifndef ULONG64_DEFINED
#define ULONG64_DEFINED
typedef unsigned __int64 ULONG64;
#endif

#ifndef ULONG_PTR_DEFINED
#define ULONG_PTR_DEFINED
typedef unsigned __int64 ULONG_PTR;
#endif

#ifndef PDWORD
typedef DWORD* PDWORD;
#endif

#ifndef PWORD
typedef WORD* PWORD;
#endif

#ifndef PRUNTIME_FUNCTION
#define PRUNTIME_FUNCTION PIMAGE_RUNTIME_FUNCTION_ENTRY
#endif

#ifndef PHYSICAL_ADDRESS_DEFINED
#define PHYSICAL_ADDRESS_DEFINED
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
#endif

typedef struct _UNICODE_STRING_EXT {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING_EXT, *PUNICODE_STRING_EXT;

typedef union _VIRT_ADDR_T {
    ULONG64 Value;
    struct {
        ULONG64 pte_index : 9;
        ULONG64 pde_index : 9;
        ULONG64 pdpte_index : 9;
        ULONG64 pml4e_index : 9;
        ULONG64 reserved : 28;
    };
} VIRT_ADDR_T, *PVIRT_ADDR_T;

#pragma pack(push, 1)

typedef struct _DOS_HEADER {
    WORD  e_magic;
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    LONG  e_lfanew;
} DOS_HEADER, *PDOS_HEADER;

typedef struct _DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} DATA_DIRECTORY, *PDATA_DIRECTORY;

typedef struct _NT_HEADERS {
    DWORD Signature;
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONG64 ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    ULONG64 SizeOfStackReserve;
    ULONG64 SizeOfStackCommit;
    ULONG64 SizeOfHeapReserve;
    ULONG64 SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    DATA_DIRECTORY ExportTable;
    DATA_DIRECTORY ImportTable;
    DATA_DIRECTORY ResourceTable;
    DATA_DIRECTORY ExceptionTable;
    DATA_DIRECTORY CertificateTable;
    DATA_DIRECTORY BaseRelocationTable;
    DATA_DIRECTORY Debug;
    DATA_DIRECTORY Architecture;
    DATA_DIRECTORY GlobalPtr;
    DATA_DIRECTORY TLSTable;
    DATA_DIRECTORY LoadConfigTable;
    DATA_DIRECTORY BoundImport;
    DATA_DIRECTORY IAT;
    DATA_DIRECTORY DelayImportDescriptor;
    DATA_DIRECTORY CLRRuntimeHeader;
    DATA_DIRECTORY Reserved;
} NT_HEADERS, *PNT_HEADERS;

typedef struct _EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} EXPORT_DIRECTORY, *PEXPORT_DIRECTORY;

typedef struct _SECTION_HEADER {
    BYTE  Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    };
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLineNumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLineNumbers;
    DWORD Characteristics;
} SECTION_HEADER, *PSECTION_HEADER;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
    PVOID  ServiceTable;
    PVOID  CounterTable;
    ULONG64 NumberOfServices;
    PVOID  ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

typedef union _PML4_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;
        ULONG64 ReadWrite : 1;
        ULONG64 UserSupervisor : 1;
        ULONG64 PageWriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Reserved1 : 1;
        ULONG64 Reserved2 : 1;
        ULONG64 Ignored : 4;
        ULONG64 Pfn : 36;
        ULONG64 Reserved3 : 4;
        ULONG64 Ignored2 : 11;
        ULONG64 NoExecute : 1;
    } Hard;
} PML4_ENTRY, *PPML4_ENTRY;

typedef union _PDPT_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;
        ULONG64 ReadWrite : 1;
        ULONG64 UserSupervisor : 1;
        ULONG64 PageWriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 PageSize : 1;
        ULONG64 Ignored : 4;
        ULONG64 Pfn : 36;
        ULONG64 Reserved : 4;
        ULONG64 Ignored2 : 11;
        ULONG64 NoExecute : 1;
    } Hard;
} PDPT_ENTRY, *PPDPT_ENTRY;

typedef union _PD_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;
        ULONG64 ReadWrite : 1;
        ULONG64 UserSupervisor : 1;
        ULONG64 PageWriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 PageSize : 1;
        ULONG64 Global : 1;
        ULONG64 Ignored : 3;
        ULONG64 Pfn : 36;
        ULONG64 Reserved : 4;
        ULONG64 Ignored2 : 11;
        ULONG64 NoExecute : 1;
    } Hard;
} PD_ENTRY, *PPD_ENTRY;

typedef union _PT_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;
        ULONG64 ReadWrite : 1;
        ULONG64 UserSupervisor : 1;
        ULONG64 PageWriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 Pat : 1;
        ULONG64 Global : 1;
        ULONG64 Ignored : 3;
        ULONG64 Pfn : 36;
        ULONG64 Reserved : 4;
        ULONG64 Ignored2 : 7;
        ULONG64 ProtectionKey : 4;
        ULONG64 NoExecute : 1;
    } Hard;
} PT_ENTRY, *PPT_ENTRY;

typedef struct _PAGE_TABLE_WALK {
    PML4_ENTRY Pml4;
    PDPT_ENTRY Pdpt;
    PD_ENTRY   Pd;
    PT_ENTRY   Pt;
} PAGE_TABLE_WALK, *PPAGE_TABLE_WALK;

typedef struct _WNODE_HEADER {
    ULONG BufferSize;
    ULONG ProviderId;
    union {
        ULONG64 HistoricalContext;
        struct {
            ULONG Version;
            ULONG Linkage;
        };
    };
    union {
        ULONG CountLost;
        HANDLE KernelHandle;
        LARGE_INTEGER TimeStamp;
    };
    GUID Guid;
    ULONG ClientContext;
    ULONG Flags;
} WNODE_HEADER, *PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES {
    WNODE_HEADER Wnode;
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG MaximumFileSize;
    ULONG LogFileMode;
    ULONG FlushTimer;
    ULONG EnableFlags;
    LONG AgeLimit;
    ULONG NumberOfBuffers;
    ULONG FreeBuffers;
    ULONG EventsLost;
    ULONG BuffersWritten;
    ULONG LogBuffersLost;
    ULONG RealTimeBuffersLost;
    HANDLE LoggerThreadId;
    ULONG LogFileNameOffset;
    ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERTIES {
    EVENT_TRACE_PROPERTIES Properties;
    ULONG64 Unknown[3];
    UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

#pragma pack(pop)

#define PTR_FROM_RVA(base, rva) ((PVOID)((ULONG_PTR)(base) + (ULONG_PTR)(rva)))

#ifndef PT_INDEX_SHIFT
#define PT_INDEX_SHIFT 12
#endif
#ifndef PD_INDEX_SHIFT
#define PD_INDEX_SHIFT 21
#endif
#ifndef PDPT_INDEX_SHIFT
#define PDPT_INDEX_SHIFT 30
#endif
#ifndef PML4_INDEX_SHIFT
#define PML4_INDEX_SHIFT 39
#endif

#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE - 1))
#endif

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define OBJ_KERNEL_HANDLE    0x00000200L