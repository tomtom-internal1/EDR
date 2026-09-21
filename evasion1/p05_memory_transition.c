#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

static const char *protect_name(DWORD p)
{
    switch (p & 0xff) {
        case PAGE_NOACCESS: return "NOACCESS";
        case PAGE_READONLY: return "R";
        case PAGE_READWRITE: return "RW";
        case PAGE_WRITECOPY: return "WC";
        case PAGE_EXECUTE_READ: return "RX";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "XWC";
        default: return "OTHER";
    }
}

int main(void)
{
    const char *poc = "P05_MEMORY_TRANSITION";
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SIZE_T size = (SIZE_T)si.dwPageSize * 4;

    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
                                        PAGE_READWRITE, 0, (DWORD)size, NULL);
    if (!section) {
        poc_emit_error(poc, 1, "SECTION_MEMORY_LIFECYCLE", "CreateFileMappingW");
        return 1;
    }

    BYTE *view = (BYTE *)MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_WRITE,
                                       0, 0, size);
    if (!view) {
        poc_emit_error(poc, 2, "SECTION_MEMORY_LIFECYCLE", "MapViewOfFile");
        CloseHandle(section);
        return 1;
    }

    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));
    VirtualQuery(view, &mbi, sizeof(mbi));

    char details[512];
    snprintf(details, sizeof(details),
             "{\"backing\":\"pagefile_section\",\"operation\":\"CreateFileMapping\","
             "\"size\":%llu,\"protect\":\"%s\",\"allocation_base\":\"%p\","
             "\"execute\":false}",
             (unsigned long long)size, protect_name(mbi.Protect), mbi.AllocationBase);
    poc_emit(poc, 1, "SectionCreate", "SECTION_MEMORY_LIFECYCLE", details);

    memcpy(view, "EDDRR-EVASION1-RW-RX-LIFECYCLE", 30);
    FlushViewOfFile(view, 30);

    poc_emit(poc, 2, "SectionWrite", "SECTION_MEMORY_LIFECYCLE",
             "{\"bytes_written\":30,\"content_class\":\"benign_marker\","
             "\"execution_performed\":false}");

    DWORD old_protect = 0;
    BOOL changed = VirtualProtect(view, size, PAGE_EXECUTE_READ, &old_protect);
    VirtualQuery(view, &mbi, sizeof(mbi));

    snprintf(details, sizeof(details),
             "{\"operation\":\"VirtualProtect\",\"result\":\"%s\","
             "\"before\":\"%s\",\"after\":\"%s\","
             "\"execute_target\":false}",
             changed ? "success" : "failure",
             protect_name(old_protect),
             protect_name(mbi.Protect));
    poc_emit(poc, 3, "ProtectionTransition", "SECTION_MEMORY_LIFECYCLE", details);

    if (changed) {
        DWORD ignored;
        VirtualProtect(view, size, PAGE_READWRITE, &ignored);
    }

    SecureZeroMemory(view, size);
    UnmapViewOfFile(view);
    CloseHandle(section);

    poc_emit(poc, 4, "SectionRelease", "SECTION_MEMORY_LIFECYCLE",
             "{\"released\":true,\"payload_execution\":false,\"restored_writable_state\":true}");

    poc_emit(poc, 5, "DetectionOracle", "SECTION_MEMORY_LIFECYCLE",
             "{\"expected_detection\":\"writable_to_executable_memory_sequence\","
             "\"correlate\":[\"SectionCreate\",\"SectionWrite\",\"ProtectionTransition\"]}");
    return 0;
}
