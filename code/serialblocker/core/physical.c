#include "physical.h"
#include "kernel.h"
#include "pagetable.h"
#include "logger.h"
#include "strings.h"

typedef struct _PHYS_MAP {
    ULONG64 VirtualAddress;
    PT_ENTRY* PteAddress;
    ULONG64 OriginalPfn;
} PHYS_MAP;

static PHYS_MAP g_PhysMaps[64];
static BOOLEAN g_PhysMemReady = FALSE;
static ULONG64 g_PhysicalMask = 0;
static ULONG64 g_LowestPage = 0;
static ULONG64 g_HighestPage = 0;

static PT_ENTRY* GetPteForAddress(ULONG64 va)
{
    PAGE_TABLE_WALK walk;
    if (!PageTableWalk(va, &walk)) return NULL;
    if (!walk.Pd.Hard.Present || walk.Pd.Hard.PageSize) return NULL;
    if (!walk.Pt.Hard.Present) return NULL;

    ULONG64 ptPa = (ULONG64)walk.Pd.Hard.Pfn << PAGE_SHIFT;
    ULONG64 ptePa = ptPa + ((va >> PT_INDEX_SHIFT) & 0x1FF) * sizeof(PT_ENTRY);
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = ptePa;
    PVOID pteVa = MmGetVirtualForPhysical(pa);
    return (PT_ENTRY*)pteVa;
}

BOOLEAN PhysMemIsValid(ULONG64 pa, SIZE_T size)
{
    if ((pa & ~g_PhysicalMask) != 0) return FALSE;
    ULONG64 endPa = pa + size - 1;
    if ((endPa & ~g_PhysicalMask) != 0) return FALSE;
    ULONG64 pfn = pa >> PAGE_SHIFT;
    return pfn >= g_LowestPage && pfn <= g_HighestPage;
}

BOOLEAN PhysMemInit(VOID)
{
    if (g_PhysMemReady) return TRUE;

    typedef PHYSICAL_MEMORY_RANGE* (NTAPI *MmGetPhysicalMemoryRanges_t)(VOID);
    MmGetPhysicalMemoryRanges_t fn = (MmGetPhysicalMemoryRanges_t)g_KernelSymbols.MmGetPhysicalMemoryRanges;
    
    if (fn) {
        PHYSICAL_MEMORY_RANGE* ranges = fn();
        if (ranges) {
            g_LowestPage = ~0ULL;
            g_HighestPage = 0;

            ULONG_PTR* ptr = (ULONG_PTR*)ranges;
            
            for (ULONG i = 0; ; i++) {
                ULONG64 base = ptr[i * 2];
                ULONG64 length = ptr[i * 2 + 1];
                
                if (base == 0 && length == 0) break;
                
                ULONG64 start = base >> PAGE_SHIFT;
                ULONG64 end = (base + length - 1) >> PAGE_SHIFT;
                
                if (start < g_LowestPage) g_LowestPage = start;
                if (end > g_HighestPage) g_HighestPage = end;
            }
            
            LoggerPrintF("[PhysMem] Memory ranges found: %llu-%llu\n", 
                        g_LowestPage, g_HighestPage);
        }
    }

    if (g_LowestPage == ~0ULL) {
        g_LowestPage = 0;
        g_HighestPage = 0x7FFFFFFF;
        LoggerPrintF("[PhysMem] Using default memory ranges\n");
    }

    int regs[4];
    __cpuid(regs, 0x80000000);
    unsigned maxExt = regs[0];
    unsigned physBits = 36;
    if (maxExt >= 0x80000008) {
        __cpuid(regs, 0x80000008);
        unsigned b = regs[0] & 0xFF;
        if (b >= 32 && b <= 52) physBits = b;
    }
    g_PhysicalMask = (physBits >= 63) ? ~0ULL : ((1ULL << physBits) - 1);

    for (int i = 0; i < 64; i++) {
        g_PhysMaps[i].VirtualAddress = (ULONG64)ExAllocatePoolWithTag(
            NonPagedPool, PAGE_SIZE, 'fuEC'
        );
        if (!g_PhysMaps[i].VirtualAddress) {
            PhysMemCleanup();
            return FALSE;
        }

        g_PhysMaps[i].PteAddress = GetPteForAddress(g_PhysMaps[i].VirtualAddress);
        if (!g_PhysMaps[i].PteAddress) {
            PhysMemCleanup();
            return FALSE;
        }

        g_PhysMaps[i].OriginalPfn = g_PhysMaps[i].PteAddress->Hard.Pfn;
    }

    g_PhysMemReady = TRUE;
    LoggerPrintF("[PhysMem] Initialized: mask=0x%llX, pages=%llu-%llu\n", 
                g_PhysicalMask, g_LowestPage, g_HighestPage);
    return TRUE;
}

VOID PhysMemCleanup(VOID)
{
    if (!g_PhysMemReady) return;

    for (int i = 0; i < 64; i++) {
        if (g_PhysMaps[i].PteAddress && g_PhysMaps[i].VirtualAddress) {
            _disable();
            g_PhysMaps[i].PteAddress->Hard.Pfn = g_PhysMaps[i].OriginalPfn;
            __invlpg((PVOID)g_PhysMaps[i].VirtualAddress);
            _enable();
        }
        if (g_PhysMaps[i].VirtualAddress) {
            ExFreePoolWithTag((PVOID)g_PhysMaps[i].VirtualAddress, 'fuEC');
            g_PhysMaps[i].VirtualAddress = 0;
        }
    }

    ZeroMem(g_PhysMaps, sizeof(g_PhysMaps));
    g_PhysMemReady = FALSE;
    LoggerPrintF("[PhysMem] Cleaned up\n");
}

BOOLEAN PhysMemRead(ULONG64 pa, PVOID buffer, SIZE_T size)
{
    if (!g_PhysMemReady || !PhysMemIsValid(pa, size)) return FALSE;

    ULONG cpu = KeGetCurrentProcessorNumber();
    if (cpu >= 64) cpu = 0;

    PHYS_MAP* map = &g_PhysMaps[cpu];
    if (!map->PteAddress || !map->VirtualAddress) return FALSE;

    ULONG64 oldPfn = map->PteAddress->Hard.Pfn;

    _disable();
    map->PteAddress->Hard.Pfn = pa >> PAGE_SHIFT;
    map->PteAddress->Hard.ReadWrite = 1;
    __invlpg((PVOID)map->VirtualAddress);

    PVOID src = (PVOID)(map->VirtualAddress + (pa & PAGE_MASK));
    __movsb((PUCHAR)buffer, (PUCHAR)src, size);

    map->PteAddress->Hard.Pfn = oldPfn;
    __invlpg((PVOID)map->VirtualAddress);
    _enable();

    return TRUE;
}

BOOLEAN PhysMemWrite(ULONG64 pa, PVOID buffer, SIZE_T size)
{
    if (!g_PhysMemReady || !PhysMemIsValid(pa, size)) return FALSE;

    ULONG cpu = KeGetCurrentProcessorNumber();
    if (cpu >= 64) cpu = 0;

    PHYS_MAP* map = &g_PhysMaps[cpu];
    if (!map->PteAddress || !map->VirtualAddress) return FALSE;

    ULONG64 oldPfn = map->PteAddress->Hard.Pfn;

    _disable();
    map->PteAddress->Hard.Pfn = pa >> PAGE_SHIFT;
    map->PteAddress->Hard.ReadWrite = 1;
    __invlpg((PVOID)map->VirtualAddress);

    PVOID dest = (PVOID)(map->VirtualAddress + (pa & PAGE_MASK));
    __movsb((PUCHAR)dest, (PUCHAR)buffer, size);

    map->PteAddress->Hard.Pfn = oldPfn;
    __invlpg((PVOID)map->VirtualAddress);
    _enable();

    return TRUE;
}