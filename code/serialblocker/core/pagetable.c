#include "pagetable.h"
#include "physical.h"
#include "logger.h"

ULONG64 g_Cr3Value = 0;

BOOLEAN PageTableWalk(ULONG64 va, PPAGE_TABLE_WALK walk)
{
    ULONG64 pml4Pa = g_Cr3Value & ~0xFFFULL;
    ULONG64 pml4ePa = pml4Pa + (((va >> PML4_INDEX_SHIFT) & 0x1FF) * sizeof(PML4_ENTRY));

    if (!PhysMemRead(pml4ePa, &walk->Pml4, sizeof(PML4_ENTRY))) return FALSE;
    if (!walk->Pml4.Hard.Present) return FALSE;

    ULONG64 pdptPa = (ULONG64)walk->Pml4.Hard.Pfn << PAGE_SHIFT;
    ULONG64 pdptePa = pdptPa + (((va >> PDPT_INDEX_SHIFT) & 0x1FF) * sizeof(PDPT_ENTRY));

    if (!PhysMemRead(pdptePa, &walk->Pdpt, sizeof(PDPT_ENTRY))) return FALSE;
    if (!walk->Pdpt.Hard.Present) return FALSE;

    if (walk->Pdpt.Hard.PageSize) {
        return TRUE;
    }

    ULONG64 pdPa = (ULONG64)walk->Pdpt.Hard.Pfn << PAGE_SHIFT;
    ULONG64 pdePa = pdPa + (((va >> PD_INDEX_SHIFT) & 0x1FF) * sizeof(PD_ENTRY));

    if (!PhysMemRead(pdePa, &walk->Pd, sizeof(PD_ENTRY))) return FALSE;
    if (!walk->Pd.Hard.Present) return FALSE;

    if (walk->Pd.Hard.PageSize) {
        return TRUE;
    }

    ULONG64 ptPa = (ULONG64)walk->Pd.Hard.Pfn << PAGE_SHIFT;
    ULONG64 ptePa = ptPa + (((va >> PT_INDEX_SHIFT) & 0x1FF) * sizeof(PT_ENTRY));

    if (!PhysMemRead(ptePa, &walk->Pt, sizeof(PT_ENTRY))) return FALSE;
    if (!walk->Pt.Hard.Present) return FALSE;

    return TRUE;
}

BOOLEAN PageTableTranslate(ULONG64 va, ULONG64* pa, ULONG32* pageSize)
{
    PAGE_TABLE_WALK walk;
    if (!PageTableWalk(va, &walk)) return FALSE;

    if (walk.Pdpt.Hard.PageSize) {
        if (pa) *pa = ((ULONG64)walk.Pdpt.Hard.Pfn << PAGE_SHIFT) | (va & 0x3FFFFFFFULL);
        if (pageSize) *pageSize = 0x40000000;
        return TRUE;
    }

    if (walk.Pd.Hard.PageSize) {
        if (pa) *pa = ((ULONG64)walk.Pd.Hard.Pfn << PAGE_SHIFT) | (va & 0x1FFFFFULL);
        if (pageSize) *pageSize = 0x200000;
        return TRUE;
    }

    if (walk.Pt.Hard.Present) {
        if (pa) *pa = ((ULONG64)walk.Pt.Hard.Pfn << PAGE_SHIFT) | (va & PAGE_MASK);
        if (pageSize) *pageSize = PAGE_SIZE;
        return TRUE;
    }

    return FALSE;
}

BOOLEAN PageTableGetPteAddress(ULONG64 va, ULONG64* ptePa)
{
    PAGE_TABLE_WALK walk;
    if (!PageTableWalk(va, &walk)) return FALSE;
    if (walk.Pd.Hard.PageSize || walk.Pdpt.Hard.PageSize) return FALSE;
    if (!walk.Pt.Hard.Present) return FALSE;

    ULONG64 ptPa = (ULONG64)walk.Pd.Hard.Pfn << PAGE_SHIFT;
    *ptePa = ptPa + ((va >> PT_INDEX_SHIFT) & 0x1FF) * sizeof(PT_ENTRY);
    return TRUE;
}

BOOLEAN PageTableSetProtection(ULONG64 va, BOOLEAN write, BOOLEAN execute, BOOLEAN user)
{
    PAGE_TABLE_WALK walk;
    if (!PageTableWalk(va, &walk)) return FALSE;

    if (walk.Pdpt.Hard.PageSize) {
        PDPT_ENTRY entry = walk.Pdpt;
        entry.Hard.ReadWrite = write ? 1 : 0;
        entry.Hard.NoExecute = execute ? 0 : 1;
        entry.Hard.UserSupervisor = user ? 1 : 0;
        ULONG64 pdptPa = (ULONG64)walk.Pml4.Hard.Pfn << PAGE_SHIFT;
        ULONG64 ptePa = pdptPa + ((va >> PDPT_INDEX_SHIFT) & 0x1FF) * sizeof(PDPT_ENTRY);
        if (!PhysMemWrite(ptePa, &entry, sizeof(PDPT_ENTRY))) return FALSE;
        __invlpg((PVOID)va);
        return TRUE;
    }

    if (walk.Pd.Hard.PageSize) {
        PD_ENTRY entry = walk.Pd;
        entry.Hard.ReadWrite = write ? 1 : 0;
        entry.Hard.NoExecute = execute ? 0 : 1;
        entry.Hard.UserSupervisor = user ? 1 : 0;
        ULONG64 pdPa = (ULONG64)walk.Pdpt.Hard.Pfn << PAGE_SHIFT;
        ULONG64 ptePa = pdPa + ((va >> PD_INDEX_SHIFT) & 0x1FF) * sizeof(PD_ENTRY);
        if (!PhysMemWrite(ptePa, &entry, sizeof(PD_ENTRY))) return FALSE;
        __invlpg((PVOID)va);
        return TRUE;
    }

    if (walk.Pt.Hard.Present) {
        PT_ENTRY entry = walk.Pt;
        entry.Hard.ReadWrite = write ? 1 : 0;
        entry.Hard.NoExecute = execute ? 0 : 1;
        entry.Hard.UserSupervisor = user ? 1 : 0;
        ULONG64 ptPa = (ULONG64)walk.Pd.Hard.Pfn << PAGE_SHIFT;
        ULONG64 ptePa = ptPa + ((va >> PT_INDEX_SHIFT) & 0x1FF) * sizeof(PT_ENTRY);
        if (!PhysMemWrite(ptePa, &entry, sizeof(PT_ENTRY))) return FALSE;
        __invlpg((PVOID)va);
        return TRUE;
    }

    return FALSE;
}

BOOLEAN PageTableSplitLargePage(ULONG64 va)
{
    PAGE_TABLE_WALK walk;
    if (!PageTableWalk(va, &walk)) return FALSE;

    if (walk.Pd.Hard.PageSize && walk.Pd.Hard.Present) {
        ULONG64 newPtVa = (ULONG64)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'fuEC');
        if (!newPtVa) return FALSE;

        PT_ENTRY* newPt = (PT_ENTRY*)newPtVa;
        ULONG64 pdePfn = walk.Pd.Hard.Pfn;

        for (int i = 0; i < 512; i++) {
            newPt[i].Value = 0;
            newPt[i].Hard.Present = 1;
            newPt[i].Hard.ReadWrite = walk.Pd.Hard.ReadWrite;
            newPt[i].Hard.UserSupervisor = walk.Pd.Hard.UserSupervisor;
            newPt[i].Hard.NoExecute = walk.Pd.Hard.NoExecute;
            newPt[i].Hard.Pfn = pdePfn + i;
        }

        PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress((PVOID)newPtVa);
        ULONG64 newPtPa = physAddr.QuadPart;

        if (!newPtPa) {
            ExFreePoolWithTag((PVOID)newPtVa, 'fuEC');
            return FALSE;
        }

        PD_ENTRY newPde;
        newPde.Value = 0;
        newPde.Hard.Present = 1;
        newPde.Hard.ReadWrite = 1;
        newPde.Hard.UserSupervisor = walk.Pd.Hard.UserSupervisor;
        newPde.Hard.Pfn = newPtPa >> PAGE_SHIFT;

        ULONG64 pdPa = (ULONG64)walk.Pdpt.Hard.Pfn << PAGE_SHIFT;
        ULONG64 pdePa = pdPa + ((va >> PD_INDEX_SHIFT) & 0x1FF) * sizeof(PD_ENTRY);

        if (!PhysMemWrite(pdePa, &newPde, sizeof(PD_ENTRY))) {
            ExFreePoolWithTag((PVOID)newPtVa, 'fuEC');
            return FALSE;
        }

        __invlpg((PVOID)va);
        return TRUE;
    }

    if (walk.Pdpt.Hard.PageSize && walk.Pdpt.Hard.Present) {
        LoggerPrintF("[PageTable] 1GB split not implemented\n");
        return FALSE;
    }

    return FALSE;
}