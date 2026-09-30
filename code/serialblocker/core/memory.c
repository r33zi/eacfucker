#include "memory.h"
#include "kernel.h"
#include "pagetable.h"
#include "physical.h"
#include "logger.h"
#include "strings.h"

ULONG64 MemoryFindCave(ULONG64 moduleBase, SIZE_T size)
{
    if (!moduleBase || size == 0) return 0;

    PDOS_HEADER dos = (PDOS_HEADER)moduleBase;
    if (dos->e_magic != 0x5A4D) return 0;

    PNT_HEADERS nt = (PNT_HEADERS)(moduleBase + dos->e_lfanew);
    if (nt->Signature != 0x4550) return 0;

    PSECTION_HEADER sections = (PSECTION_HEADER)((ULONG_PTR)nt + 
                               nt->SizeOfOptionalHeader + 0x18);

    for (WORD i = 0; i < nt->NumberOfSections; i++) {
        if (!(sections[i].Characteristics & 0x20000000)) continue;
        if (sections[i].VirtualSize < size) continue;

        ULONG64 start = moduleBase + sections[i].VirtualAddress;
        ULONG64 end = start + sections[i].VirtualSize;

        UCHAR* ptr = (UCHAR*)start;
        UCHAR* caveStart = NULL;
        SIZE_T caveSize = 0;

        while ((ULONG64)ptr < end) {
            UCHAR b = *ptr;
            if (b == 0x00 || b == 0x90 || b == 0xCC) {
                if (!caveStart) caveStart = ptr;
                caveSize++;
                if (caveSize >= size) {
                    ULONG64 caveVa = (ULONG64)caveStart;
                    if (!MemoryIsCoveredByRuntimeFunction(moduleBase, caveVa, size)) {
                        return caveVa;
                    }
                    caveStart = NULL;
                    caveSize = 0;
                }
            } else {
                caveStart = NULL;
                caveSize = 0;
            }
            ptr++;
        }
    }

    return 0;
}

ULONG64 MemoryFindCaveInDriver(SIZE_T size)
{
    if (!g_DriverBase || !g_DriverSize) return 0;

    ULONG64 pageBase = g_DriverBase & ~0x1FFFFFULL;
    ULONG64 pageEnd = pageBase + 0x200000;
    ULONG64 searchStart = g_DriverBase + g_DriverSize;
    ULONG64 searchEnd = pageEnd - size;

    if (searchStart >= pageEnd) return 0;

    UCHAR* base = (UCHAR*)searchStart;
    SIZE_T scanSize = searchEnd - searchStart;

    for (SIZE_T i = 0; i <= scanSize; i++) {
        BOOLEAN found = TRUE;
        for (SIZE_T j = 0; j < size; j++) {
            if (base[i + j] != 0x00) {
                found = FALSE;
                i += j;
                break;
            }
        }
        if (!found) continue;

        ULONG64 caveVa = searchStart + i;

        ULONG64 pa;
        if (!PageTableTranslate(caveVa, &pa, NULL)) {
            i++;
            continue;
        }

        PageTableSetProtection(caveVa, TRUE, TRUE, FALSE);

        return caveVa;
    }

    return 0;
}

BOOLEAN MemoryIsAddressValid(PVOID addr)
{
    typedef BOOLEAN (NTAPI *MmIsAddressValid_t)(PVOID);
    static MmIsAddressValid_t fn = NULL;
    if (!fn) fn = (MmIsAddressValid_t)g_KernelSymbols.MmIsAddressValid;
    if (!fn) return FALSE;
    return fn(addr);
}

BOOLEAN MemoryGetImageFileName(PEPROCESS process, char* buffer, SIZE_T size)
{
    if (!buffer || !size) return FALSE;
    ZeroMem(buffer, size);

    if (!MemoryIsAddressValid(process)) return FALSE;

    typedef char* (NTAPI *PsGetProcessImageFileName_t)(PEPROCESS);
    PsGetProcessImageFileName_t fn = 
        (PsGetProcessImageFileName_t)g_KernelSymbols.PsGetProcessImageFileName;
    if (!fn) return FALSE;

    char* name = fn(process);
    if (!name) return FALSE;

    SIZE_T len = StrLenA(name);
    if (len >= size) len = size - 1;
    CopyMem(buffer, name, len);
    buffer[len] = '\0';

    return TRUE;
}


BOOLEAN MemoryIsCoveredByRuntimeFunction(ULONG64 moduleBase, ULONG64 address, SIZE_T size)
{
    if (!moduleBase) return FALSE;

    PDOS_HEADER dos = (PDOS_HEADER)moduleBase;
    if (dos->e_magic != 0x5A4D) return FALSE;

    PNT_HEADERS nt = (PNT_HEADERS)(moduleBase + dos->e_lfanew);
    if (nt->Signature != 0x4550) return FALSE;

    if (!nt->ExceptionTable.VirtualAddress || !nt->ExceptionTable.Size) {
        return FALSE;
    }

    ULONG32 startRva = (ULONG32)(address - moduleBase);
    ULONG32 endRva = startRva + (ULONG32)size;

    PIMAGE_RUNTIME_FUNCTION_ENTRY functions = (PIMAGE_RUNTIME_FUNCTION_ENTRY)
        PTR_FROM_RVA(moduleBase, nt->ExceptionTable.VirtualAddress);
    ULONG count = nt->ExceptionTable.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

    for (ULONG i = 0; i < count; i++) {
        ULONG32 begin = functions[i].BeginAddress;
        ULONG32 end = functions[i].EndAddress;
        if (startRva < end && endRva > begin) {
            return TRUE;
        }
    }

    return FALSE;
}