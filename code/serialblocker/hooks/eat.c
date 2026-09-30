#include "eat.h"

static ULONG g_EatHookCount = 0;

NTSTATUS EatHookInstall(ULONG64 moduleBase, const char* name, PVOID hook, PVOID* original)
{
    if (!moduleBase || !name || !hook) return STATUS_INVALID_PARAMETER;

    PDOS_HEADER dos = (PDOS_HEADER)moduleBase;
    if (dos->e_magic != 0x5A4D) return STATUS_INVALID_IMAGE_FORMAT;

    PNT_HEADERS nt = (PNT_HEADERS)(moduleBase + dos->e_lfanew);
    if (nt->Signature != 0x4550) return STATUS_INVALID_IMAGE_FORMAT;

    PEXPORT_DIRECTORY exp = (PEXPORT_DIRECTORY)PTR_FROM_RVA(moduleBase, nt->ExportTable.VirtualAddress);
    if (!exp || !exp->NumberOfNames) return STATUS_NOT_FOUND;

    DWORD* names = (DWORD*)PTR_FROM_RVA(moduleBase, exp->AddressOfNames);
    DWORD* funcs = (DWORD*)PTR_FROM_RVA(moduleBase, exp->AddressOfFunctions);
    WORD* ords = (WORD*)PTR_FROM_RVA(moduleBase, exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* cur = (char*)PTR_FROM_RVA(moduleBase, names[i]);
        if (!cur) continue;

        if (StrCmpA(cur, name) == 0) {
            WORD ordinal = ords[i];
            DWORD originalRva = funcs[ordinal];
            ULONG64 functionAddress = moduleBase + originalRva;
            ULONG32* slotAddress = (ULONG32*)&funcs[ordinal];

            if (original) *original = (PVOID)functionAddress;

            ULONG64 delta = (ULONG64)hook - moduleBase;
            if (delta > 0x7FFFFFFF) {
                
                
                
                
                
                
                ("[EatHook] Hook too far from module base\n");
                return STATUS_UNSUCCESSFUL;
            }
            ULONG32 hookRva = (ULONG32)delta;

            PMDL mdl = IoAllocateMdl(slotAddress, sizeof(ULONG32), FALSE, FALSE, NULL);
            if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

            __try {
                MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                IoFreeMdl(mdl);
                return STATUS_ACCESS_VIOLATION;
            }

            ULONG32* mapped = (ULONG32*)MmMapLockedPagesSpecifyCache(
                mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute
            );
            if (!mapped) {
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                return STATUS_UNSUCCESSFUL;
            }

            MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
            InterlockedExchange((volatile LONG*)mapped, (LONG)hookRva);

            MmUnmapLockedPages(mapped, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);

            PEAT_HOOK_STATE state = (PEAT_HOOK_STATE)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(EAT_HOOK_STATE), 'fuEC'
            );
            if (state) {
                state->ExportName = name;
                state->ModuleBase = moduleBase;
                state->OriginalAddress = functionAddress;
                state->SlotAddress = slotAddress;
                state->OriginalRva = originalRva;
                state->HookRva = hookRva;
                state->Active = TRUE;
            }

            LoggerPrintF("[EatHook] Hooked %s at 0x%llX -> 0x%llX\n", name, functionAddress, (ULONG64)hook);
            g_EatHookCount++;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS EatHookRemove(PEAT_HOOK_STATE state)
{
    if (!state || !state->Active) return STATUS_INVALID_PARAMETER;

    PMDL mdl = IoAllocateMdl(state->SlotAddress, sizeof(ULONG32), FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        ULONG32* mapped = (ULONG32*)MmMapLockedPagesSpecifyCache(
            mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute
        );
        if (mapped) {
            MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
            InterlockedExchange((volatile LONG*)mapped, (LONG)state->OriginalRva);
            MmUnmapLockedPages(mapped, mdl);
        }
        MmUnlockPages(mdl);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return STATUS_ACCESS_VIOLATION;
    }

    IoFreeMdl(mdl);
    state->Active = FALSE;
    if (g_EatHookCount > 0) g_EatHookCount--;

    LoggerPrintF("[EatHook] Removed %s\n", state->ExportName);
    return STATUS_SUCCESS;
}