#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include "poc_common.h"

typedef LONG NTSTATUS;
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION_LAB {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_LAB;

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

static DWORD toolhelp_parent(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    DWORD parent = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                parent = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return parent;
}

static int child_mode(void)
{
    poc_emit("P02_PARENT_CONTEXT", 1, "ChildStart", "PARENT_PROCESS_CONTEXT",
             "{\"role\":\"child\",\"sleep_ms\":1200}");
    Sleep(1200);
    poc_emit("P02_PARENT_CONTEXT", 2, "ChildStop", "PARENT_PROCESS_CONTEXT",
             "{\"role\":\"child\"}");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0)
        return child_mode();

    const char *poc = "P02_PARENT_CONTEXT";
    unsigned long seq = 1;
    char exe[MAX_PATH];
    DWORD exe_len = GetModuleFileNameA(NULL, exe, MAX_PATH);
    if (!exe_len || exe_len >= MAX_PATH) {
        poc_emit_error(poc, seq++, "PARENT_PROCESS_CONTEXT", "GetModuleFileNameA");
        return 1;
    }

    char command[MAX_PATH + 32];
    snprintf(command, sizeof(command), "\"%s\" --child", exe);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    poc_emit(poc, seq++, "ProcessCreateIntent", "PARENT_PROCESS_CONTEXT",
             "{\"child_mode\":true,\"ground_truth_sources\":[\"Toolhelp32\",\"NtQueryInformationProcess\"]}");

    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        poc_emit_error(poc, seq++, "PARENT_PROCESS_CONTEXT", "CreateProcessA");
        return 1;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtQueryInformationProcess ntq = ntdll ?
        (PFN_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess") : NULL;

    DWORD observed_parent = toolhelp_parent(pi.dwProcessId);
    PROCESS_BASIC_INFORMATION_LAB pbi;
    ZeroMemory(&pbi, sizeof(pbi));
    ULONG returned = 0;
    NTSTATUS status = ntq ?
        ntq(pi.hProcess, ProcessBasicInformation, &pbi, (ULONG)sizeof(pbi), &returned) :
        (NTSTATUS)-1;

    unsigned long nt_parent = (unsigned long)pbi.InheritedFromUniqueProcessId;

    char details[512];
    snprintf(details, sizeof(details),
             "{\"child_pid\":%lu,\"toolhelp_parent_pid\":%lu,"
             "\"ntquery_parent_pid\":%lu,\"ntstatus\":%ld,"
             "\"sources_agree\":%s}",
             (unsigned long)pi.dwProcessId,
             (unsigned long)observed_parent,
             nt_parent,
             (long)status,
             (observed_parent != 0 && observed_parent == nt_parent) ? "true" : "false");
    poc_emit(poc, seq++, "LineageCrossCheck", "PARENT_PROCESS_CONTEXT", details);

    DWORD wait = WaitForSingleObject(pi.hProcess, 3000);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    snprintf(details, sizeof(details),
             "{\"wait_result\":%lu,\"child_exit_code\":%lu,"
             "\"observed_creator_pid\":%lu,\"current_pid\":%lu}",
             (unsigned long)wait, (unsigned long)exit_code,
             (unsigned long)observed_parent, (unsigned long)GetCurrentProcessId());
    poc_emit(poc, seq++, "ProcessLifecycle", "PARENT_PROCESS_CONTEXT", details);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    poc_emit(poc, seq++, "DetectionOracle", "PARENT_PROCESS_CONTEXT",
             "{\"expected_detection\":\"lineage_inconsistency_if_sources_disagree\","
             "\"confidence_rule\":\"two-source_reconciliation\","
             "\"pid_reuse_must_be_considered\":true}");
    return 0;
}
