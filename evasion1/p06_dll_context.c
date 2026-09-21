#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "poc_common.h"

int main(void)
{
    const char *poc = "P06_DLL_CONTEXT";
    WCHAR path[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, path, MAX_PATH);

    if (!len || len >= MAX_PATH) {
        poc_emit_error(poc, 1, "DLL_LOAD_CONTEXT", "GetModuleFileNameW");
        return 1;
    }

    WCHAR *slash = wcsrchr(path, L'\\');
    if (slash) *(slash + 1) = L'\0';

    WCHAR dll_path[MAX_PATH];
    _snwprintf_s(dll_path, MAX_PATH, _TRUNCATE,
                 L"%sevasion1_fixture.dll", path);

    poc_emit(poc, 1, "ImageLoadIntent", "DLL_LOAD_CONTEXT",
             "{\"fixture\":\"evasion1_fixture.dll\",\"expected_provenance\":\"suite-local\",\"signature\":\"benign-test-fixture\"}");

    HMODULE mod = LoadLibraryExW(dll_path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!mod) {
        poc_emit_error(poc, 2, "DLL_LOAD_CONTEXT", "LoadLibraryExW");
        return 1;
    }

    char detail[256];
    snprintf(detail, sizeof(detail),
             "{\"module\":\"evasion1_fixture.dll\",\"load_address\":\"%p\","
             "\"path_context\":\"suite-local\",\"execution_side_effects\":false}",
             (void *)mod);
    poc_emit(poc, 2, "ImageLoad", "DLL_LOAD_CONTEXT", detail);

    FARPROC marker = GetProcAddress(mod, "Evasion1FixtureMarker");
    poc_emit(poc, 3, "ExportInspection", "DLL_LOAD_CONTEXT",
             marker ? "{\"export\":\"Evasion1FixtureMarker\",\"present\":true}"
                    : "{\"export\":\"Evasion1FixtureMarker\",\"present\":false}");

    FreeLibrary(mod);
    poc_emit(poc, 4, "ImageUnload", "DLL_LOAD_CONTEXT",
             "{\"module\":\"evasion1_fixture.dll\",\"unloaded\":true}");
    return 0;
}
