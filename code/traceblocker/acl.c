#include "acl.h"
#include <ntstrsafe.h>
#pragma warning(disable: 4996)
#define RtlStringCbPrintfW(a,b,c,...) DbgPrint(__VA_ARGS__)

static const WCHAR* g_PathHosts = L"\\??\\C:\\Windows\\System32\\drivers\\etc\\hosts";
static const WCHAR* g_PathWindows = L"\\??\\C:\\Windows\\";
static const WCHAR* g_PathProgramData = L"\\??\\C:\\ProgramData\\";
static const WCHAR* g_PathUsers = L"\\??\\C:\\Users";

static const WCHAR* g_RelEAC = L"EasyAntiCheat";
static const WCHAR* g_RelEACLogs = L"EasyAntiCheat\\Logs";
static const WCHAR* g_RelEACLauncher = L"EasyAntiCheat\\Launcher";
static const WCHAR* g_RelFortniteLogs = L"FortniteGame\\Saved\\Logs";
static const WCHAR* g_RelFortniteCrashes = L"FortniteGame\\Saved\\Crashes";
static const WCHAR* g_RelFortniteConfig = L"FortniteGame\\Saved\\Config";
static const WCHAR* g_RelEpicLogs = L"Epic Games\\Launcher\\Logs";
static const WCHAR* g_RelEpicSaved = L"Epic Games\\Launcher\\Saved";

typedef enum _BLOCK_RULE_TYPE {
    RULE_EXACT,
    RULE_WINDIR,
    RULE_PROGRAMDATA,
    RULE_USER_LOCAL,
    RULE_USER_ROAMING,
} BLOCK_RULE_TYPE;

typedef struct _BLOCK_RULE {
    BLOCK_RULE_TYPE Type;
    const WCHAR*    Path;
} BLOCK_RULE;

static const BLOCK_RULE g_BlockRules[] = {
    { RULE_USER_ROAMING, L"EasyAntiCheat" },
    { RULE_PROGRAMDATA, L"EasyAntiCheat" },
    { RULE_USER_LOCAL, L"EasyAntiCheat\\Logs" },
    { RULE_USER_LOCAL, L"FortniteGame\\Saved\\Logs" },
    { RULE_USER_LOCAL, L"FortniteGame\\Saved\\Crashes" },
    { RULE_USER_LOCAL, L"Epic Games\\Launcher\\Logs" },
    { RULE_USER_LOCAL, L"Epic Games\\Launcher\\Saved" },
    { RULE_PROGRAMDATA, L"EasyAntiCheat\\Launcher" },
    { RULE_USER_LOCAL, L"FortniteGame\\Saved\\Config" },
    { RULE_EXACT, L"\\??\\C:\\Windows\\System32\\drivers\\etc\\hosts" },
};

static volatile LONG g_BlockThreadActive = 0;
static volatile LONG g_StopBlock = 0;

static VOID SetEmptyDacl(const WCHAR* fullPath)
{
    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, fullPath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hFile;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = ZwCreateFile(
        &hFile,
        WRITE_DAC,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) return;

    SECURITY_DESCRIPTOR sd;
    RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);

    ULONG aclSize = sizeof(ACL);
    PACL pAcl = (PACL)ExAllocatePoolWithTag(NonPagedPool, aclSize, 'fuEC');
    if (!pAcl) {
        ZwClose(hFile);
        return;
    }

    RtlCreateAcl(pAcl, aclSize, ACL_REVISION);
    RtlSetDaclSecurityDescriptor(&sd, TRUE, pAcl, FALSE);

    status = ZwSetSecurityObject(hFile, DACL_SECURITY_INFORMATION, &sd);
    if (NT_SUCCESS(status)) {
        LoggerPrintF("[ACL] Blocked: %ws\n", fullPath);
    }

    ExFreePoolWithTag(pAcl, 'fuEC');
    ZwClose(hFile);
}

static VOID ApplyRule(const BLOCK_RULE* rule, const WCHAR* userProfile)
{
    WCHAR fullPath[512];

    switch (rule->Type) {
    case RULE_EXACT:
        SetEmptyDacl(rule->Path);
        break;

    case RULE_WINDIR:
        RtlStringCbPrintfW(fullPath, ARRAYSIZE(fullPath), L"%ws%ws", g_PathWindows, rule->Path);
        SetEmptyDacl(fullPath);
        break;

    case RULE_PROGRAMDATA:
        RtlStringCbPrintfW(fullPath, ARRAYSIZE(fullPath), L"%ws%ws", g_PathProgramData, rule->Path);
        SetEmptyDacl(fullPath);
        break;

    case RULE_USER_LOCAL:
        if (userProfile) {
            RtlStringCbPrintfW(fullPath, ARRAYSIZE(fullPath), L"%ws\\AppData\\Local\\%ws",
                                userProfile, rule->Path);
            SetEmptyDacl(fullPath);
        }
        break;

    case RULE_USER_ROAMING:
        if (userProfile) {
            RtlStringCbPrintfW(fullPath, ARRAYSIZE(fullPath), L"%ws\\AppData\\Roaming\\%ws",
                                userProfile, rule->Path);
            SetEmptyDacl(fullPath);
        }
        break;
    }
}

static VOID BlockInternal(VOID)
{
    for (SIZE_T i = 0; i < ARRAYSIZE(g_BlockRules); i++) {
        if (g_BlockRules[i].Type == RULE_EXACT ||
            g_BlockRules[i].Type == RULE_WINDIR ||
            g_BlockRules[i].Type == RULE_PROGRAMDATA) {
            ApplyRule(&g_BlockRules[i], NULL);
        }
    }

    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, g_PathUsers);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hDir;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = ZwOpenFile(
        &hDir,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) return;

    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, 4096, 'fuEC');
    if (!buffer) {
        ZwClose(hDir);
        return;
    }

    BOOLEAN restart = TRUE;
    while (TRUE) {
        status = ZwQueryDirectoryFile(
            hDir, NULL, NULL, NULL,
            &iosb, buffer, 4096,
            FileDirectoryInformation,
            TRUE, NULL, restart
        );
        if (!NT_SUCCESS(status)) break;

        restart = FALSE;
        PFILE_DIRECTORY_INFORMATION info = (PFILE_DIRECTORY_INFORMATION)buffer;

        while (TRUE) {
            if (info->FileNameLength > 0 && info->FileName[0] != L'.') {
                SIZE_T chars = info->FileNameLength / sizeof(WCHAR);
                if (chars < 256) {
                    WCHAR profile[256];
                    CopyMem(profile, info->FileName, info->FileNameLength);
                    profile[chars] = L'\0';

                    WCHAR fullProfile[512];
                    RtlStringCbPrintfW(fullProfile, ARRAYSIZE(fullProfile), L"%ws\\%ws",
                                        g_PathUsers, profile);

                    for (SIZE_T i = 0; i < ARRAYSIZE(g_BlockRules); i++) {
                        if (g_BlockRules[i].Type == RULE_USER_LOCAL ||
                            g_BlockRules[i].Type == RULE_USER_ROAMING) {
                            ApplyRule(&g_BlockRules[i], fullProfile);
                        }
                    }
                }
            }

            if (info->NextEntryOffset == 0) break;
            info = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
        }
    }

    ExFreePoolWithTag(buffer, 'fuEC');
    ZwClose(hDir);
}

NTSTATUS AclBlockerRun(VOID)
{
    LoggerPrintF("[ACL] Running block pass\n");
    BlockInternal();
    return STATUS_SUCCESS;
}

static VOID BlockThreadProc(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER interval;
    interval.QuadPart = -5000000LL;

    while (!g_StopBlock) {
        __try {
            InterlockedIncrement(&g_BlockThreadActive);
            BlockInternal();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LoggerPrintF("[ACL] Exception in block thread\n");
        }
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID WatchdogProc(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER interval;
    interval.QuadPart = -30000000LL;

    LONG lastHeartbeat = 0;

    while (!g_StopBlock) {
        KeDelayExecutionThread(KernelMode, FALSE, &interval);

        LONG current = InterlockedCompareExchange(&g_BlockThreadActive, 0, 0);

        if (current == lastHeartbeat) {
            LoggerPrintF("[ACL] Watchdog: respawning thread\n");
            HANDLE hThread;
            NTSTATUS status = PsCreateSystemThread(
                &hThread,
                THREAD_ALL_ACCESS,
                NULL,
                NULL,
                NULL,
                BlockThreadProc,
                NULL
            );
            if (NT_SUCCESS(status)) ZwClose(hThread);
        }

        lastHeartbeat = current;
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS AclBlockerStart(VOID)
{
    g_StopBlock = FALSE;
    g_BlockThreadActive = 0;

    HANDLE hThread;

    NTSTATUS status = PsCreateSystemThread(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        BlockThreadProc,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[ACL] Failed to create block thread: 0x%X\n", status);
        return status;
    }
    ZwClose(hThread);

    status = PsCreateSystemThread(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        WatchdogProc,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        LoggerPrintF("[ACL] Failed to create watchdog: 0x%X\n", status);
        g_StopBlock = TRUE;
        return status;
    }
    ZwClose(hThread);

    LoggerPrintF("[ACL] Started block thread + watchdog\n");
    return STATUS_SUCCESS;
}

VOID AclBlockerStop(VOID)
{
    g_StopBlock = TRUE;
    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
    LoggerPrintF("[ACL] Stopped block thread\n");
}