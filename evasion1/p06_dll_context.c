#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "poc_common.h"

static int get_directory(WCHAR *out, DWORD capacity)
{
    DWORD len = GetModuleFileNameW(NULL, out, capacity);
    if (!len || len >= capacity) return 0;
    WCHAR *slash = wcsrchr(out, L'\\');
    if (!slash) return 0;
    *slash = L'\0';
    return 1;
}

int main(void)
{
    const char *poc = "P06_DLL_CONTEXT";
    WCHAR dir[MAX_PATH];
    WCHAR full[MAX_PATH];

    if (!get_directory(dir, MAX_PATH)) {
        poc_emit_error(poc, 1, "DLL_LOAD_CONTEXT", "GetModuleDirectory");
        return 1;
    }

    _snwprintf_s(full, MAX_PATH, _TRUNCATE,
                 L"%sevasion1_fixture.dll", dir);

    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                  LOAD_LIBRARY_SEARCH_USER_DIRS)) {
        poc_emit_error(poc, 1, "DLL_LOAD_CONTEXT", "SetDefaultDllDirectories");
        return 1;
    }

    DLL_DIRECTORY_COOKIE cookie = AddDllDirectory(dir);
    if (!cookie) {
        poc_emit_error(poc, 1, "DLL_LOAD_CONTEXT", "AddDllDirectory");
        return 1;
    }

    poc_emit(poc, 1, "DllSearchPolicy", "DLL_LOAD_CONTEXT",
             "{\"policy\":\"SYSTEM32+USER_DIRS\",\"search_source\":\"suite-local-directory\","
             "\"unsafe_current_directory_search\":false}");

    char path_ascii[MAX_PATH * 2];
    WideCharToMultiByte(CP_UTF8, 0, full, -1, path_ascii, sizeof(path_ascii), NULL, NULL);
    char details[640];
    snprintf(details, sizeof(details),
             "{\"load_request\":\"evasion1_fixture.dll\",\"expected_full_path\":\"%s\","
             "\"load_flags\":\"LOAD_LIBRARY_SEARCH_USER_DIRS\",\"provenance\":\"suite-local\"}",
             path_ascii);
    poc_emit(poc, 2, "ImageLoadIntent", "DLL_LOAD_CONTEXT", details);

    HMODULE mod = LoadLibraryExW(L"evasion1_fixture.dll", NULL,
                                 LOAD_LIBRARY_SEARCH_USER_DIRS);
    if (!mod) {
        poc_emit_error(poc, 3, "DLL_LOAD_CONTEXT", "LoadLibraryExW");
        RemoveDllDirectory(cookie);
        return 1;
    }

    WCHAR loaded_path[MAX_PATH];
    DWORD len = GetModuleFileNameW(mod, loaded_path, MAX_PATH);
    WideCharToMultiByte(CP_UTF8, 0, loaded_path, -1, path_ascii, sizeof(path_ascii), NULL, NULL);

    snprintf(details, sizeof(details),
             "{\"resolved_path\":\"%s\",\"path_matches_expected\":%s,"
             "\"module_address\":\"%p\",\"side_effect_payload\":false}",
             path_ascii, (len && _wcsicmp(loaded_path, full) == 0) ? "true" : "false",
             (void *)mod);
    poc_emit(poc, 3, "ImageLoad", "DLL_LOAD_CONTEXT", details);

    FARPROC marker = GetProcAddress(mod, "Evasion1FixtureMarker");
    poc_emit(poc, 4, "ExportResolution", "DLL_LOAD_CONTEXT",
             marker ? "{\"export\":\"Evasion1FixtureMarker\",\"present\":true}"
                    : "{\"export\":\"Evasion1FixtureMarker\",\"present\":false}");

    FreeLibrary(mod);
    RemoveDllDirectory(cookie);

    poc_emit(poc, 5, "ImageUnload", "DLL_LOAD_CONTEXT",
             "{\"module\":\"evasion1_fixture.dll\",\"unloaded\":true}");

    poc_emit(poc, 6, "DetectionOracle", "DLL_LOAD_CONTEXT",
             "{\"expected_detection\":\"unexpected_module_provenance\","
             "\"baseline_rule\":\"module_path_must_be_explainable\","
             "\"this_fixture_expected_benign\":true}");
    return 0;
}
