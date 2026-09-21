#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    const char *poc = "P01_SYSCALL_VISIBILITY";
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC nt_protect = ntdll ? GetProcAddress(ntdll, "NtProtectVirtualMemory") : NULL;
    unsigned long seq = 1;

    poc_emit(poc, seq++, "ProcessStart", "SYSCALL_PATH_VISIBILITY",
             "{\"model\":\"user_api_baseline\",\"operation\":\"memory_protection\",\"status\":\"begin\"}");

    if (!ntdll || !nt_protect) {
        poc_emit_error(poc, seq++, "SYSCALL_PATH_VISIBILITY", "resolve_ntdll_export");
        return 1;
    }

    poc_emit(poc, seq++, "ApiResolution", "SYSCALL_PATH_VISIBILITY",
             "{\"module\":\"ntdll.dll\",\"export\":\"NtProtectVirtualMemory\",\"resolved\":true}");

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SIZE_T region = si.dwPageSize;
    BYTE *page = (BYTE *)VirtualAlloc(NULL, region, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!page) {
        poc_emit_error(poc, seq++, "SYSCALL_PATH_VISIBILITY", "VirtualAlloc");
        return 1;
    }

    page[0] = 0x41;
    DWORD old_protect = 0;
    BOOL ok = VirtualProtect(page, region, PAGE_READONLY, &old_protect);

    poc_emit(poc, seq++, "UserApiOperation", "SYSCALL_PATH_VISIBILITY",
             ok ? "{\"operation\":\"VirtualProtect\",\"result\":\"success\"}"
                : "{\"operation\":\"VirtualProtect\",\"result\":\"failure\"}");

    poc_emit(poc, seq++, "SemanticEquivalent", "SYSCALL_PATH_VISIBILITY",
             "{\"operation\":\"NtProtectVirtualMemory\",\"execution\":\"NOT_PERFORMED\",\"visibility_path\":\"synthetic_kernel_equivalent\"}");

    VirtualProtect(page, region, old_protect, &old_protect);
    SecureZeroMemory(page, region);
    VirtualFree(page, 0, MEM_RELEASE);

    poc_emit(poc, seq++, "ProcessStop", "SYSCALL_PATH_VISIBILITY",
             "{\"status\":\"complete\",\"operational_syscall\":false}");
    return 0;
}
