#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "poc_common.h"

static const char *protect_name(DWORD p)
{
    switch (p & 0xff) {
        case PAGE_READONLY: return "R";
        case PAGE_READWRITE: return "RW";
        case PAGE_EXECUTE_READ: return "RX";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE: return "X";
        default: return "OTHER";
    }
}

int main(void)
{
    const char *id = "A08_SEC_IMAGE_MAPPING";
    WCHAR path[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (!n || n >= MAX_PATH) {
        adv_error(id, 1, "SEC_IMAGE_PROVENANCE", "GetModuleFileNameW");
        return 1;
    }

    WCHAR *slash = wcsrchr(path, L'\\');
    if (!slash) return 1;
    *slash = L'\0';

    WCHAR dll[MAX_PATH];
    _snwprintf_s(dll, MAX_PATH, _TRUNCATE, L"%sevasion1_fixture.dll", path);

    HANDLE file = CreateFileW(dll, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        adv_error(id, 1, "SEC_IMAGE_PROVENANCE", "CreateFileW");
        return 1;
    }

    HANDLE mapping = CreateFileMappingW(file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!mapping) {
        adv_error(id, 2, "SEC_IMAGE_PROVENANCE", "CreateFileMappingW_SEC_IMAGE");
        CloseHandle(file);
        return 1;
    }

    PVOID view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        adv_error(id, 3, "SEC_IMAGE_PROVENANCE", "MapViewOfFile");
        CloseHandle(mapping);
        CloseHandle(file);
        return 1;
    }

    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));
    VirtualQuery(view, &mbi, sizeof(mbi));

    char d[512];
    snprintf(d, sizeof(d),
             "{\"source\":\"evasion1_fixture.dll\","
             "\"mapping_type\":\"SEC_IMAGE\",\"base\":\"%p\","
             "\"allocation_base\":\"%p\",\"protect\":\"%s\","
             "\"code_executed\":false}",
             view, mbi.AllocationBase, protect_name(mbi.Protect));
    adv_emit(id, 1, "ImageSectionMapped", "SEC_IMAGE_PROVENANCE", d);

    BOOL mz = (*(const WORD *)view == IMAGE_DOS_SIGNATURE);
    snprintf(d, sizeof(d),
             "{\"pe_header_magic_MZ\":%s,\"mapping_valid\":true,"
             "\"execution_from_mapping\":false}", mz ? "true" : "false");
    adv_emit(id, 2, "ImageInspection", "SEC_IMAGE_PROVENANCE", d);

    UnmapViewOfFile(view);
    CloseHandle(mapping);
    CloseHandle(file);

    adv_emit(id, 3, "DetectionOracle", "SEC_IMAGE_PROVENANCE",
             "{\"expected_detection\":\"image_backed_memory_provenance\","
             "\"correlate\":[\"file_identity\",\"SEC_IMAGE_mapping\",\"module_context\"]}");
    return 0;
}
