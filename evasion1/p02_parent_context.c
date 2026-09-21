#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "poc_common.h"

static DWORD find_parent_pid(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
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

int main(void)
{
    const char *poc = "P02_PARENT_CONTEXT";
    DWORD pid = GetCurrentProcessId();
    DWORD observed = find_parent_pid(pid);
    DWORD reported = observed ? observed + 1 : 1;
    unsigned long seq = 1;

    poc_emit(poc, seq++, "ProcessContext", "PARENT_PROCESS_CONTEXT",
             "{\"relationship\":\"self\",\"context_source\":\"toolhelp\",\"status\":\"observed\"}");

    char details[256];
    snprintf(details, sizeof(details),
             "{\"process_pid\":%lu,\"observed_parent_pid\":%lu,\"reported_parent_pid\":%lu,"
             "\"consistency\":%s,\"spoofing_performed\":false}",
             (unsigned long)pid,
             (unsigned long)observed,
             (unsigned long)reported,
             observed == reported ? "true" : "false");

    poc_emit(poc, seq++, "LineageComparison", "PARENT_PROCESS_CONTEXT", details);
    poc_emit(poc, seq++, "DetectionOracle", "PARENT_PROCESS_CONTEXT",
             "{\"expected_detection\":\"parent_context_inconsistency\",\"severity\":\"medium\"}");

    return 0;
}
