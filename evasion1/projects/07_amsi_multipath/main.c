#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#pragma comment(lib, "amsi.lib")
#include "poc_common.h"

#define MAX_TEST_INPUT (4ULL * 1024ULL * 1024ULL)

static const char *result_name(AMSI_RESULT r)
{
    if (r == AMSI_RESULT_CLEAN) return "CLEAN";
    if (r == AMSI_RESULT_NOT_DETECTED) return "NOT_DETECTED";
    if (r >= AMSI_RESULT_DETECTED) return "DETECTED";
    return "OTHER";
}

static void emit_scan(unsigned long seq,
                      const char *method,
                      const char *mode,
                      AMSI_RESULT r,
                      HRESULT hr,
                      unsigned long long bytes)
{
    char d[512];

    snprintf(d, sizeof(d),
             "{\"method\":\"%s\",\"mode\":\"%s\","
             "\"bytes\":%llu,\"hresult\":\"0x%08lX\","
             "\"result\":%lu,\"result_name\":\"%s\","
             "\"result_is_malware\":%s}",
             method,
             mode,
             bytes,
             (unsigned long)hr,
             (unsigned long)r,
             result_name(r),
             AmsiResultIsMalware(r) ? "true" : "false");

    adv_emit("A07_AMSI_MULTIPATH", seq, "AmsiScan",
             "AMSI_MULTIPATH_VALIDATION", d);
}

static int load_file(const wchar_t *path, BYTE **buffer, DWORD *size)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    LARGE_INTEGER li;
    BYTE *data = NULL;
    DWORD wanted = 0;
    DWORD got = 0;

    *buffer = NULL;
    *size = 0;

    h = CreateFileW(path,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (!GetFileSizeEx(h, &li) || li.QuadPart < 0 ||
        (unsigned long long)li.QuadPart > MAX_TEST_INPUT ||
        (unsigned long long)li.QuadPart > 0xFFFFFFFFULL) {
        CloseHandle(h);
        SetLastError(ERROR_FILE_TOO_LARGE);
        return 0;
    }

    wanted = (DWORD)li.QuadPart;

    if (wanted != 0) {
        data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, wanted);
        if (!data) {
            CloseHandle(h);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }

        if (!ReadFile(h, data, wanted, &got, NULL) || got != wanted) {
            DWORD e = GetLastError();
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(h);
            SetLastError(e ? e : ERROR_READ_FAULT);
            return 0;
        }
    }

    CloseHandle(h);
    *buffer = data;
    *size = wanted;
    return 1;
}

int wmain(int argc, wchar_t **argv)
{
    const char *id = "A07_AMSI_MULTIPATH";
    HAMSICONTEXT ctx = NULL;
    HAMSISESSION session = NULL;
    const wchar_t *external_path = NULL;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--input") == 0 && i + 1 < argc) {
            external_path = argv[++i];
            continue;
        }

        SetLastError(ERROR_INVALID_PARAMETER);
        adv_error(id, 1, "AMSI_MULTIPATH_VALIDATION", "argument parsing");
        return 1;
    }

    HRESULT hr = AmsiInitialize(L"EDDRR-Evasion1-AMSI-Multipath", &ctx);
    if (FAILED(hr)) {
        SetLastError((DWORD)hr);
        adv_error(id, 2, "AMSI_MULTIPATH_VALIDATION", "AmsiInitialize");
        return 1;
    }

    hr = AmsiOpenSession(ctx, &session);
    if (FAILED(hr)) {
        SetLastError((DWORD)hr);
        adv_error(id, 2, "AMSI_MULTIPATH_VALIDATION", "AmsiOpenSession");
        AmsiUninitialize(ctx);
        return 1;
    }

    const wchar_t *benign =
        L"EDDRR-Evasion1 benign multipath validation input";

    AMSI_RESULT string_result = AMSI_RESULT_CLEAN;
    hr = AmsiScanString(ctx,
                        benign,
                        L"benign-string",
                        session,
                        &string_result);
    emit_scan(3,
              "AmsiScanString",
              "built_in_benign",
              string_result,
              hr,
              (unsigned long long)wcslen(benign));

    BYTE *external_buffer = NULL;
    DWORD external_size = 0;
    const BYTE *buffer = (const BYTE *)benign;
    DWORD buffer_size = (DWORD)(wcslen(benign) * sizeof(wchar_t));
    const wchar_t *content_name = L"benign-buffer";
    const char *mode = "built_in_benign";

    if (external_path) {
        if (!load_file(external_path, &external_buffer, &external_size)) {
            adv_error(id, 4, "AMSI_MULTIPATH_VALIDATION", "load external input");
            AmsiCloseSession(ctx, session);
            AmsiUninitialize(ctx);
            return 1;
        }

        buffer = external_buffer;
        buffer_size = external_size;
        content_name = L"external-validation-input";
        mode = "external_file";
    }

    AMSI_RESULT buffer_result = AMSI_RESULT_CLEAN;
    hr = AmsiScanBuffer(ctx,
                        (PVOID)buffer,
                        buffer_size,
                        content_name,
                        session,
                        &buffer_result);

    emit_scan(4,
              "AmsiScanBuffer",
              mode,
              buffer_result,
              hr,
              (unsigned long long)buffer_size);

    HRESULT notify_hr = AmsiNotifyOperation(
        ctx,
        NULL,
        L"EDDRR_Evasion1_AMSI_Operation",
        external_path ? L"external-validation-operation"
                      : L"benign-test-operation");

    char d[512];
    snprintf(d, sizeof(d),
             "{\"notify_hresult\":\"0x%08lX\","
             "\"string_result_is_malware\":%s,"
             "\"buffer_result_is_malware\":%s,"
             "\"buffer_mode\":\"%s\"}",
             (unsigned long)notify_hr,
             AmsiResultIsMalware(string_result) ? "true" : "false",
             AmsiResultIsMalware(buffer_result) ? "true" : "false",
             mode);

    adv_emit(id, 5, "CrossPathCorrelation",
             "AMSI_MULTIPATH_VALIDATION", d);

    adv_emit(id, 6, "DetectionOracle",
             "AMSI_MULTIPATH_VALIDATION",
             "{\"expected_detection\":\"inconsistent_AMSI_result_behavior\","
             "\"signals\":[\"AmsiScanString\",\"AmsiScanBuffer\",\"AmsiNotifyOperation\"],"
             "\"unexpected_clean_validation\":\"investigate_provider_health_and_integrity\","
             "\"known_test_input_is_external\":true}");

    if (external_buffer) {
        HeapFree(GetProcessHeap(), 0, external_buffer);
    }

    AmsiCloseSession(ctx, session);
    AmsiUninitialize(ctx);
    return 0;
}
