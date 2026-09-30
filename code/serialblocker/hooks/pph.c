#include "pph.h"
#include "shadow.h"
#include "memory.h"
#include "strings.h"

SIZE_T CalculateHookSize(ULONG64 targetPa, SIZE_T minSize)
{
    UCHAR buffer[64];
    if (!PhysMemRead(targetPa, buffer, sizeof(buffer))) return 0;

    SIZE_T totalLen = 0;
    while (totalLen < minSize && totalLen < sizeof(buffer)) {
        HDE_DISASSEMBLY hde;
        HdeDisassemble(&buffer[totalLen], &hde);
        if (hde.len == 0) break;
        totalLen += hde.len;
    }
    return totalLen;
}

NTSTATUS PphHookCreate(ULONG64 targetAddress, PVOID* original, PPPH_HOOK_STATE* outState)
{
    if (!targetAddress || !outState) return STATUS_INVALID_PARAMETER;

    PAGE_TABLE_WALK walk;
    if (!PageTableWalk(targetAddress, &walk)) return STATUS_UNSUCCESSFUL;

    if (walk.Pdpt.Hard.PageSize) {
        if (!PageTableSplitLargePage(targetAddress)) return STATUS_UNSUCCESSFUL;
    }
    if (walk.Pd.Hard.PageSize) {
        if (!PageTableSplitLargePage(targetAddress)) return STATUS_UNSUCCESSFUL;
    }

    ULONG64 targetPa;
    if (!PageTableTranslate(targetAddress, &targetPa, NULL)) return STATUS_UNSUCCESSFUL;

    SIZE_T hookSize = CalculateHookSize(targetPa, 14);
    if (hookSize < 14) return STATUS_UNSUCCESSFUL;

    ULONG64 caveAddress = MemoryFindCaveInDriver(hookSize + 14);
    if (!caveAddress) return STATUS_UNSUCCESSFUL;

    UCHAR originalBytes[64];
    if (!PhysMemRead(targetPa, originalBytes, sizeof(originalBytes))) return STATUS_UNSUCCESSFUL;

    if (!PhysMemWrite(caveAddress, originalBytes, hookSize)) return STATUS_UNSUCCESSFUL;

    UCHAR jumpBack[14];
    jumpBack[0] = 0xFF;
    jumpBack[1] = 0x25;
    *(ULONG32*)&jumpBack[2] = 0;
    *(ULONG64*)&jumpBack[6] = targetAddress + hookSize;

    if (!PhysMemWrite(caveAddress + hookSize, jumpBack, sizeof(jumpBack))) return STATUS_UNSUCCESSFUL;

    PPPH_HOOK_STATE state = (PPPH_HOOK_STATE)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(PPH_HOOK_STATE), 'fuEC'
    );
    if (!state) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(state->OriginalBytes, originalBytes, hookSize);
    state->HookSize = hookSize;
    state->TrampolineAddress = caveAddress;
    state->HookedPageAddress = targetAddress;
    state->HookedPagePhysical = targetPa;
    state->TargetPhysical = targetPa;

    if (original) *original = (PVOID)caveAddress;

    *outState = state;

    LoggerPrintF("[PPH] Hook created at 0x%llX -> trampoline 0x%llX\n", targetAddress, caveAddress);
    return STATUS_SUCCESS;
}

NTSTATUS PphHookEnable(PPPH_HOOK_STATE state, PVOID hookFunction)
{
    if (!state || !hookFunction) return STATUS_INVALID_PARAMETER;

    if (!ShadowBuild(state->HookedPagePhysical, state->HookedPageAddress,
        &state->Shadow)) {
        return STATUS_UNSUCCESSFUL;
    }

    UCHAR hookBytes[14];
    hookBytes[0] = 0xFF;
    hookBytes[1] = 0x25;
    *(ULONG32*)&hookBytes[2] = 0;
    *(ULONG64*)&hookBytes[6] = (ULONG64)hookFunction;

    if (!PhysMemWrite(state->HookedPagePhysical, hookBytes, 14)) {
        ShadowTeardown(&state->Shadow);
        return STATUS_UNSUCCESSFUL;
    }

    if (state->HookSize > 14) {
        UCHAR nops[48];
        RtlZeroMemory(nops, sizeof(nops));
        for (SIZE_T i = 0; i < state->HookSize - 14; i++) nops[i] = 0x90;
        if (!PhysMemWrite(state->HookedPagePhysical + 14, nops, state->HookSize - 14)) {
            ShadowTeardown(&state->Shadow);
            return STATUS_UNSUCCESSFUL;
        }
    }

    ShadowSwapToHooked(&state->Shadow);

    LoggerPrintF("[PPH] Hook enabled at 0x%llX\n", state->HookedPageAddress);
    return STATUS_SUCCESS;
}

NTSTATUS PphHookDisable(PPPH_HOOK_STATE state)
{
    if (!state) return STATUS_INVALID_PARAMETER;

    ShadowSwapToClean(&state->Shadow);

    LoggerPrintF("[PPH] Hook disabled\n");
    return STATUS_SUCCESS;
}

NTSTATUS PphHookRemove(PPPH_HOOK_STATE state)
{
    if (!state) return STATUS_INVALID_PARAMETER;

    if (!PhysMemWrite(state->HookedPagePhysical, state->OriginalBytes, state->HookSize)) {
        return STATUS_UNSUCCESSFUL;
    }

    ShadowTeardown(&state->Shadow);

    ExFreePoolWithTag(state, 'fuEC');

    LoggerPrintF("[PPH] Hook removed\n");
    return STATUS_SUCCESS;
}