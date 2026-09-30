#include "ssdt.h"
#include "kernel.h"
#include "logger.h"
#include "strings.h"

static PSERVICE_DESCRIPTOR_TABLE g_KeServiceDescriptorTable = NULL;
static PSERVICE_DESCRIPTOR_TABLE g_KeServiceDescriptorTableShadow = NULL;
static ULONG64 g_ShadowTableFound = 0;

BOOLEAN SsdtFindShadowTable(VOID)
{
    ULONG64 ntBase = g_KernelBase;
    if (!ntBase) {
        LoggerPrintF("[SSDT] Kernel base not found\n");
        return FALSE;
    }

    ULONG64 shadowTable = KernelGetExport("KeServiceDescriptorTableShadow");
    if (shadowTable) {
        g_ShadowTableFound = shadowTable;
        g_KeServiceDescriptorTableShadow = (PSERVICE_DESCRIPTOR_TABLE)shadowTable;
        LoggerPrintF("[SSDT] Found shadow table at 0x%llX\n", shadowTable);
        return TRUE;
    }

    LoggerPrintF("[SSDT] Shadow table not found\n");
    return FALSE;
}

ULONG SsdtGetSyscallIndex(const char* name)
{
    if (!name) return (ULONG)-1;

    UNICODE_STRING fileName;
    RtlInitUnicodeString(&fileName, L"\\SystemRoot\\System32\\ntdll.dll");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &fileName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE fileHandle = NULL;

    NTSTATUS status = ZwCreateFile(
        &fileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[SSDT] Failed to open ntdll.dll: 0x%X\n", status);
        return (ULONG)-1;
    }

    FILE_STANDARD_INFORMATION stdInfo;
    status = ZwQueryInformationFile(fileHandle, &iosb,
                                    &stdInfo, sizeof(stdInfo),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        return (ULONG)-1;
    }

    ULONG fileSize = stdInfo.EndOfFile.LowPart;
    if (fileSize < 0x1000 || fileSize > 0x10000000) {
        ZwClose(fileHandle);
        return (ULONG)-1;
    }

    PUCHAR fileData = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, fileSize, 'fuEC');
    if (!fileData) {
        ZwClose(fileHandle);
        return (ULONG)-1;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iosb,
                        fileData, fileSize, &offset, NULL);
    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(fileData, 'fuEC');
        return (ULONG)-1;
    }

    PDOS_HEADER dos = (PDOS_HEADER)fileData;
    if (dos->e_magic != 0x5A4D || dos->e_lfanew >= (LONG)fileSize) {
        ExFreePoolWithTag(fileData, 'fuEC');
        return (ULONG)-1;
    }

    PNT_HEADERS nt = (PNT_HEADERS)(fileData + dos->e_lfanew);
    if (nt->Signature != 0x4550) {
        ExFreePoolWithTag(fileData, 'fuEC');
        return (ULONG)-1;
    }

    DWORD expRva = nt->ExportTable.VirtualAddress;
    DWORD expSize = nt->ExportTable.Size;
    if (expRva == 0 || expSize == 0) {
        ExFreePoolWithTag(fileData, 'fuEC');
        return (ULONG)-1;
    }

    DWORD expOffset = 0;
    PSECTION_HEADER sections = (PSECTION_HEADER)((ULONG_PTR)nt + 
                              nt->SizeOfOptionalHeader + 0x18);
    for (WORD i = 0; i < nt->NumberOfSections; i++) {
        DWORD va = sections[i].VirtualAddress;
        DWORD vsz = sections[i].VirtualSize;
        if (expRva >= va && expRva < va + vsz) {
            expOffset = (expRva - va) + sections[i].PointerToRawData;
            break;
        }
    }

    if (expOffset == 0 || expOffset + sizeof(EXPORT_DIRECTORY) > fileSize) {
        ExFreePoolWithTag(fileData, 'fuEC');
        return (ULONG)-1;
    }

    PEXPORT_DIRECTORY exp = (PEXPORT_DIRECTORY)(fileData + expOffset);

    DWORD namesOffset = 0, funcsOffset = 0, ordsOffset = 0;
    for (WORD i = 0; i < nt->NumberOfSections; i++) {
        DWORD va = sections[i].VirtualAddress;
        DWORD vsz = sections[i].VirtualSize;
        if (exp->AddressOfNames >= va && exp->AddressOfNames < va + vsz) {
            namesOffset = (exp->AddressOfNames - va) + sections[i].PointerToRawData;
        }
        if (exp->AddressOfFunctions >= va && exp->AddressOfFunctions < va + vsz) {
            funcsOffset = (exp->AddressOfFunctions - va) + sections[i].PointerToRawData;
        }
        if (exp->AddressOfNameOrdinals >= va && exp->AddressOfNameOrdinals < va + vsz) {
            ordsOffset = (exp->AddressOfNameOrdinals - va) + sections[i].PointerToRawData;
        }
    }

    if (namesOffset == 0 || funcsOffset == 0 || ordsOffset == 0) {
        ExFreePoolWithTag(fileData, 'fuEC');
        return (ULONG)-1;
    }

    PDWORD names = (PDWORD)(fileData + namesOffset);
    PDWORD funcs = (PDWORD)(fileData + funcsOffset);
    PWORD ords = (PWORD)(fileData + ordsOffset);

    ULONG result = (ULONG)-1;
    SIZE_T nameLen = StrLenA(name);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD nameOffset = 0;
        DWORD nameRva = names[i];
        for (WORD j = 0; j < nt->NumberOfSections; j++) {
            DWORD va = sections[j].VirtualAddress;
            DWORD vsz = sections[j].VirtualSize;
            if (nameRva >= va && nameRva < va + vsz) {
                nameOffset = (nameRva - va) + sections[j].PointerToRawData;
                break;
            }
        }
        if (nameOffset == 0 || nameOffset + nameLen + 1 > fileSize) continue;

        char* curName = (char*)(fileData + nameOffset);
        if (StrCmpA(curName, name) == 0) {
            WORD ordinal = ords[i];
            DWORD funcRva = funcs[ordinal];

            DWORD funcOffset = 0;
            for (WORD j = 0; j < nt->NumberOfSections; j++) {
                DWORD va = sections[j].VirtualAddress;
                DWORD vsz = sections[j].VirtualSize;
                if (funcRva >= va && funcRva < va + vsz) {
                    funcOffset = (funcRva - va) + sections[j].PointerToRawData;
                    break;
                }
            }

            if (funcOffset != 0 && funcOffset + 32 <= fileSize) {
                PUCHAR funcBytes = fileData + funcOffset;
                for (int j = 0; j < 32 && funcOffset + j + 5 <= fileSize; j++) {
                    if (funcBytes[j] == 0xC2 || funcBytes[j] == 0xC3) break;
                    if (funcBytes[j] == 0xB8) {
                        result = *(ULONG*)(funcBytes + j + 1);
                        break;
                    }
                }
            }
            break;
        }
    }

    ExFreePoolWithTag(fileData, 'fuEC');

    if (result != (ULONG)-1) {
        LoggerPrintF("[SSDT] %s -> 0x%X\n", name, result);
    } else {
        LoggerPrintF("[SSDT] Failed to find syscall: %s\n", name);
    }

    return result;
}

ULONG64 SsdtGetHandler(ULONG index)
{
    if (!g_KeServiceDescriptorTable) {
        g_KeServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)
            g_KernelSymbols.KeServiceDescriptorTable;
        if (!g_KeServiceDescriptorTable) {
            LoggerPrintF("[SSDT] KeServiceDescriptorTable not found\n");
            return 0;
        }
    }

    ULONG idx = index & 0xFFF;
    BOOLEAN isWin32k = (index & 0x1000) != 0;

    PSERVICE_DESCRIPTOR_TABLE table = g_KeServiceDescriptorTable;

    if (isWin32k) {
        if (!g_KeServiceDescriptorTableShadow) {
            g_KeServiceDescriptorTableShadow = (PSERVICE_DESCRIPTOR_TABLE)
                KernelGetExport("KeServiceDescriptorTableShadow");
            if (!g_KeServiceDescriptorTableShadow) {
                g_ShadowTableFound = SsdtFindShadowTable();
                if (g_ShadowTableFound) {
                    g_KeServiceDescriptorTableShadow = (PSERVICE_DESCRIPTOR_TABLE)
                        g_ShadowTableFound;
                }
            }
        }
        if (g_KeServiceDescriptorTableShadow) {
            table = g_KeServiceDescriptorTableShadow + 1;
        } else {
            LoggerPrintF("[SSDT] Win32k syscall but shadow table not found\n");
            return 0;
        }
    }

    if (!table || !table->ServiceTable) {
        LoggerPrintF("[SSDT] ServiceTable is NULL\n");
        return 0;
    }

    if (idx >= table->NumberOfServices) {
        LoggerPrintF("[SSDT] Index 0x%X out of range (max 0x%llX)\n", 
                    idx, table->NumberOfServices);
        return 0;
    }

    LONG* serviceTable = (LONG*)table->ServiceTable;
    LONG encoded = serviceTable[idx];
    LONG disp = encoded >> 4;
    ULONG64 handler = (ULONG64)serviceTable + disp;

    if (!handler || !MemoryIsAddressValid((PVOID)handler)) {
        LoggerPrintF("[SSDT] Invalid handler for index 0x%X\n", idx);
        return 0;
    }

    return handler;
}

