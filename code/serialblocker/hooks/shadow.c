#include "shadow.h"

#define PAGE_SIZE 0x1000

static ULONG32 FindFreePml4Slot(ULONG64 systemPml4Pa)
{
    for (ULONG32 idx = 257; idx < 511; idx++) {
        PML4_ENTRY entry;
        ULONG64 ptePa = systemPml4Pa + (idx * sizeof(PML4_ENTRY));
        if (!PhysMemRead(ptePa, &entry, sizeof(PML4_ENTRY))) continue;
        if (!entry.Hard.Present) return idx;
    }
    return (ULONG32)-1;
}

static ULONG64 AllocPage(VOID)
{
    ULONG64 va = (ULONG64)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'fuEC');
    if (!va) return 0;

    PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress((PVOID)va);
    ULONG64 pa = physAddr.QuadPart;

    if (!pa) {
        ExFreePoolWithTag((PVOID)va, 'fuEC');
        return 0;
    }
    RtlZeroMemory((PVOID)va, PAGE_SIZE);
    return pa;
}

BOOLEAN ShadowBuild(ULONG64 privatePa, ULONG64 hookedVa, PSHADOW_MAPPING mapping)
{
    ULONG64 systemPml4Pa = __readcr3() & ~0xFFFULL;

    ULONG32 slot = FindFreePml4Slot(systemPml4Pa);
    if (slot == (ULONG32)-1) return FALSE;

    ULONG64 shadowPml4Pa = AllocPage();
    ULONG64 shadowPdptPa = AllocPage();
    ULONG64 shadowPdPa = AllocPage();
    ULONG64 shadowPtPa = AllocPage();

    if (!shadowPml4Pa || !shadowPdptPa || !shadowPdPa || !shadowPtPa) {
        return FALSE;
    }

    UCHAR buffer[PAGE_SIZE];
    if (!PhysMemRead(systemPml4Pa, buffer, PAGE_SIZE)) return FALSE;
    if (!PhysMemWrite(shadowPml4Pa, buffer, PAGE_SIZE)) return FALSE;

    ULONG64 shadowVaBase = (ULONG64)slot << PML4_INDEX_SHIFT;
    shadowVaBase |= 0xFFFF000000000000ULL;
    ULONG64 shadowVa = (shadowVaBase & ~PAGE_MASK) | (hookedVa & PAGE_MASK);

    VIRT_ADDR_T sv;
    sv.Value = shadowVa;

    PML4_ENTRY pml4e;
    pml4e.Value = 0;
    pml4e.Hard.Present = 1;
    pml4e.Hard.ReadWrite = 1;
    pml4e.Hard.Pfn = shadowPdptPa >> PAGE_SHIFT;
    PhysMemWrite(shadowPml4Pa + (sv.pml4e_index * sizeof(PML4_ENTRY)), &pml4e, sizeof(PML4_ENTRY));

    PDPT_ENTRY pdpte;
    pdpte.Value = 0;
    pdpte.Hard.Present = 1;
    pdpte.Hard.ReadWrite = 1;
    pdpte.Hard.Pfn = shadowPdPa >> PAGE_SHIFT;
    PhysMemWrite(shadowPdptPa + (sv.pdpte_index * sizeof(PDPT_ENTRY)), &pdpte, sizeof(PDPT_ENTRY));

    PD_ENTRY pde;
    pde.Value = 0;
    pde.Hard.Present = 1;
    pde.Hard.ReadWrite = 1;
    pde.Hard.Pfn = shadowPtPa >> PAGE_SHIFT;
    PhysMemWrite(shadowPdPa + (sv.pde_index * sizeof(PD_ENTRY)), &pde, sizeof(PD_ENTRY));

    PT_ENTRY pte;
    pte.Value = 0;
    pte.Hard.Present = 1;
    pte.Hard.ReadWrite = 0;
    pte.Hard.NoExecute = 0;
    pte.Hard.Pfn = privatePa >> PAGE_SHIFT;
    PhysMemWrite(shadowPtPa + (sv.pte_index * sizeof(PT_ENTRY)), &pte, sizeof(PT_ENTRY));

    mapping->Pml4Physical = shadowPml4Pa;
    mapping->PdptPhysical = shadowPdptPa;
    mapping->PdPhysical = shadowPdPa;
    mapping->PtPhysical = shadowPtPa;
    mapping->ShadowAddress = shadowVa;
    mapping->Pml4Index = slot;
    mapping->Active = TRUE;

    LoggerPrintF("[Shadow] Built shadow mapping at slot %u\n", slot);
    return TRUE;
}

BOOLEAN ShadowSwapToHooked(PSHADOW_MAPPING mapping)
{
    if (!mapping || !mapping->Active) return FALSE;

    ULONG64 systemPml4Pa = __readcr3() & ~0xFFFULL;
    ULONG64 pml4ePa = systemPml4Pa + (mapping->Pml4Index * sizeof(PML4_ENTRY));

    PML4_ENTRY pml4e;
    pml4e.Value = 0;
    pml4e.Hard.Present = 1;
    pml4e.Hard.ReadWrite = 1;
    pml4e.Hard.Pfn = mapping->Pml4Physical >> PAGE_SHIFT;

    if (!PhysMemWrite(pml4ePa, &pml4e, sizeof(PML4_ENTRY))) return FALSE;

    __invlpg((PVOID)mapping->ShadowAddress);
    LoggerPrintF("[Shadow] Swapped to hooked\n");
    return TRUE;
}

BOOLEAN ShadowSwapToClean(PSHADOW_MAPPING mapping)
{
    if (!mapping || !mapping->Active) return FALSE;

    ULONG64 systemPml4Pa = __readcr3() & ~0xFFFULL;
    ULONG64 pml4ePa = systemPml4Pa + (mapping->Pml4Index * sizeof(PML4_ENTRY));

    PML4_ENTRY pml4e;
    pml4e.Value = 0;

    if (!PhysMemWrite(pml4ePa, &pml4e, sizeof(PML4_ENTRY))) return FALSE;

    __invlpg((PVOID)mapping->ShadowAddress);
    LoggerPrintF("[Shadow] Swapped to clean\n");
    return TRUE;
}

BOOLEAN ShadowTeardown(PSHADOW_MAPPING mapping)
{
    if (!mapping || !mapping->Active) return FALSE;

    mapping->Active = FALSE;

    LoggerPrintF("[Shadow] Teardown complete\n");
    return TRUE;
}