#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>
#pragma comment(lib, "amsi.lib")
#pragma comment(lib, "bcrypt.lib")
#include "poc_common.h"

#define MAX_TEST_INPUT (4ULL * 1024ULL * 1024ULL)
#define DEFAULT_REPEATS 2U
#define MAX_REPEATS 20U

typedef struct {
    const char *name;
    AMSI_RESULT first_result;
    HRESULT first_hr;
    unsigned int observed;
    unsigned int hr_failures;
    unsigned int result_changes;
    BOOL initialized;
} path_state;

static const char *result_name(AMSI_RESULT r)
{
    if (r == AMSI_RESULT_CLEAN) return "CLEAN";
    if (r == AMSI_RESULT_NOT_DETECTED) return "NOT_DETECTED";
    if (r >= AMSI_RESULT_DETECTED) return "DETECTED";
    return "OTHER";
}

static double elapsed_us(const LARGE_INTEGER *start,
                         const LARGE_INTEGER *end,
                         const LARGE_INTEGER *frequency)
{
    return ((double)(end->QuadPart - start->QuadPart) * 1000000.0) /
           (double)frequency->QuadPart;
}

static int sha256(const BYTE *data, ULONG len, BYTE out[32])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR object = NULL;
    ULONG object_len = 0;
    ULONG cb = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st < 0) return 0;

    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                           (PUCHAR)&object_len, sizeof(object_len), &cb, 0);
    if (st < 0) goto fail;

    object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, object_len);
    if (!object) goto fail;

    st = BCryptCreateHash(alg, &hash, object, object_len, NULL, 0, 0);
    if (st < 0) goto fail;

    if (len != 0) {
        st = BCryptHashData(hash, (PUCHAR)data, len, 0);
        if (st < 0) goto fail;
    }

    st = BCryptFinishHash(hash, out, 32, 0);
    if (st < 0) goto fail;

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    HeapFree(GetProcessHeap(), 0, object);
    return 1;

fail:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (object) HeapFree(GetProcessHeap(), 0, object);
    return 0;
}

static void hex32(const BYTE h[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i * 2] = hex[h[i] >> 4];
        out[i * 2 + 1] = hex[h[i] & 0x0f];
    }
    out[64] = '\0';
}

static void emit_scan(unsigned long seq,
                      const char *method,
                      const char *session_mode,
                      const char *input_mode,
                      AMSI_RESULT r,
                      HRESULT hr,
                      unsigned long long bytes,
                      double latency_us)
{
    char d[640];

    snprintf(d, sizeof(d),
             "{\"method\":\"%s\",\"session\":\"%s\","
             "\"input\":\"%s\",\"bytes\":%llu,"
             "\"hresult\":\"0x%08lX\",\"hresult_success\":%s,"
             "\"result\":%lu,\"result_name\":\"%s\","
             "\"result_is_malware\":%s,\"latency_us\":%.2f}",
             method,
             session_mode,
             input_mode,
             bytes,
             (unsigned long)hr,
             SUCCEEDED(hr) ? "true" : "false",
             (unsigned long)r,
             result_name(r),
             AmsiResultIsMalware(r) ? "true" : "false",
             latency_us);

    adv_emit("A07_AMSI_MULTIPATH", seq, "AmsiScan",
             "AMSI_MULTIPATH_VALIDATION", d);
}

static void observe_path(path_state *state, AMSI_RESULT result, HRESULT hr)
{
    if (!state->initialized) {
        state->first_result = result;
        state->first_hr = hr;
        state->initialized = TRUE;
    } else if (state->first_result != result) {
        state->result_changes++;
    }

    if (FAILED(hr)) {
        state->hr_failures++;
    }

    state->observed++;
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
    if (h == INVALID_HANDLE_VALUE) return 0;

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

static void emit_module_context(void)
{
    WCHAR path[MAX_PATH];
    DWORD n = GetSystemDirectoryW(path, MAX_PATH);
    if (!n || n >= MAX_PATH || n + 9 >= MAX_PATH) return;

    wcscat_s(path, MAX_PATH, L"\\amsi.dll");

    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path, &handle);
    char version[64] = "unavailable";

    if (size != 0) {
        BYTE *block = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
        if (block && GetFileVersionInfoW(path, 0, size, block)) {
            VS_FIXEDFILEINFO *ffi = NULL;
            UINT ffi_size = 0;

            if (VerQueryValueW(block, L"\\", (LPVOID *)&ffi, &ffi_size) &&
                ffi && ffi_size >= sizeof(*ffi)) {
                snprintf(version, sizeof(version), "%u.%u.%u.%u",
                         HIWORD(ffi->dwFileVersionMS),
                         LOWORD(ffi->dwFileVersionMS),
                         HIWORD(ffi->dwFileVersionLS),
                         LOWORD(ffi->dwFileVersionLS));
            }
        }
        if (block) HeapFree(GetProcessHeap(), 0, block);
    }

    HMODULE amsi = GetModuleHandleW(L"amsi.dll");
    if (!amsi) amsi = LoadLibraryW(L"amsi.dll");

    char d[512];
    snprintf(d, sizeof(d),
             "{\"dll\":\"amsi.dll\",\"version\":\"%s\","
             "\"module_loaded\":%s}",
             version,
             amsi ? "true" : "false");

    adv_emit("A07_AMSI_MULTIPATH", 1, "AmsiModuleContext",
             "AMSI_MULTIPATH_VALIDATION", d);
}

static int parse_uint(const wchar_t *s, unsigned int *value)
{
    wchar_t *end = NULL;
    unsigned long v;

    if (!s || !*s) return 0;
    v = wcstoul(s, &end, 10);
    if (*end != L'\0' || v == 0 || v > MAX_REPEATS) return 0;

    *value = (unsigned int)v;
    return 1;
}

int wmain(int argc, wchar_t **argv)
{
    const char *id = "A07_AMSI_MULTIPATH";
    const wchar_t *external_path = NULL;
    unsigned int repeats = DEFAULT_REPEATS;
    HAMSICONTEXT ctx = NULL;
    HAMSISESSION session = NULL;
    BYTE *external_buffer = NULL;
    DWORD external_size = 0;
    BYTE input_hash[32];
    char input_hash_hex[65];
    const char *input_mode = "built_in_benign";
    int exit_code = 1;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--input") == 0 && i + 1 < argc) {
            external_path = argv[++i];
        } else if (_wcsicmp(argv[i], L"--repeat") == 0 && i + 1 < argc) {
            if (!parse_uint(argv[++i], &repeats)) {
                SetLastError(ERROR_INVALID_PARAMETER);
                adv_error(id, 1, "AMSI_MULTIPATH_VALIDATION",
                          "invalid repeat count");
                return 1;
            }
        } else {
            SetLastError(ERROR_INVALID_PARAMETER);
            adv_error(id, 1, "AMSI_MULTIPATH_VALIDATION",
                      "argument parsing");
            return 1;
        }
    }

    emit_module_context();

    const wchar_t *benign_w =
        L"EDDRR-Evasion1 benign multipath validation input";
    const char *benign_a =
        "EDDRR-Evasion1 benign multipath validation input";

    const BYTE *buffer = (const BYTE *)benign_a;
    DWORD buffer_size = (DWORD)strlen(benign_a);

    if (external_path) {
        if (!load_file(external_path, &external_buffer, &external_size)) {
            adv_error(id, 2, "AMSI_MULTIPATH_VALIDATION",
                      "load external input");
            goto cleanup;
        }

        buffer = external_buffer;
        buffer_size = external_size;
        input_mode = "external_file";
    }

    if (!sha256(buffer, buffer_size, input_hash)) {
        adv_error(id, 2, "AMSI_MULTIPATH_VALIDATION", "input SHA-256");
        goto cleanup;
    }

    hex32(input_hash, input_hash_hex);

    {
        char d[512];
        snprintf(d, sizeof(d),
                 "{\"input\":\"%s\",\"bytes\":%lu,"
                 "\"sha256\":\"%s\",\"repeat_count\":%u}",
                 input_mode,
                 (unsigned long)buffer_size,
                 input_hash_hex,
                 repeats);

        adv_emit(id, 3, "InputContext",
                 "AMSI_MULTIPATH_VALIDATION", d);
    }

    HRESULT hr = AmsiInitialize(
        L"EDDRR-Evasion1-AMSI-Multipath", &ctx);

    if (FAILED(hr)) {
        SetLastError((DWORD)hr);
        adv_error(id, 4, "AMSI_MULTIPATH_VALIDATION",
                  "AmsiInitialize");
        goto cleanup;
    }

    hr = AmsiOpenSession(ctx, &session);
    if (FAILED(hr)) {
        SetLastError((DWORD)hr);
        adv_error(id, 4, "AMSI_MULTIPATH_VALIDATION",
                  "AmsiOpenSession");
        goto cleanup;
    }

    path_state string_session =
        { "AmsiScanString/session", 0, S_OK, 0, 0, 0, FALSE };
    path_state string_nosession =
        { "AmsiScanString/no_session", 0, S_OK, 0, 0, 0, FALSE };
    path_state buffer_session =
        { "AmsiScanBuffer/session", 0, S_OK, 0, 0, 0, FALSE };
    path_state buffer_nosession =
        { "AmsiScanBuffer/no_session", 0, S_OK, 0, 0, 0, FALSE };

    LARGE_INTEGER frequency;
    if (!QueryPerformanceFrequency(&frequency) ||
        frequency.QuadPart <= 0) {
        SetLastError(ERROR_FUNCTION_FAILED);
        adv_error(id, 5, "AMSI_MULTIPATH_VALIDATION",
                  "QueryPerformanceFrequency");
        goto cleanup;
    }

    for (unsigned int round = 1; round <= repeats; ++round) {
        LARGE_INTEGER start;
        LARGE_INTEGER end;
        AMSI_RESULT result;

        QueryPerformanceCounter(&start);
        result = AMSI_RESULT_CLEAN;
        hr = AmsiScanString(
            ctx, benign_w, L"built-in-benign", session, &result);
        QueryPerformanceCounter(&end);

        observe_path(&string_session, result, hr);
        emit_scan(10 + ((round - 1) * 4),
                  "AmsiScanString", "session", "built_in_benign",
                  result, hr,
                  (unsigned long long)(wcslen(benign_w) * sizeof(wchar_t)),
                  elapsed_us(&start, &end, &frequency));

        QueryPerformanceCounter(&start);
        result = AMSI_RESULT_CLEAN;
        hr = AmsiScanString(
            ctx, benign_w, L"built-in-benign", NULL, &result);
        QueryPerformanceCounter(&end);

        observe_path(&string_nosession, result, hr);
        emit_scan(11 + ((round - 1) * 4),
                  "AmsiScanString", "no_session", "built_in_benign",
                  result, hr,
                  (unsigned long long)(wcslen(benign_w) * sizeof(wchar_t)),
                  elapsed_us(&start, &end, &frequency));

        QueryPerformanceCounter(&start);
        result = AMSI_RESULT_CLEAN;
        hr = AmsiScanBuffer(
            ctx, (PVOID)buffer, buffer_size,
            L"validation-buffer", session, &result);
        QueryPerformanceCounter(&end);

        observe_path(&buffer_session, result, hr);
        emit_scan(12 + ((round - 1) * 4),
                  "AmsiScanBuffer", "session", input_mode,
                  result, hr,
                  (unsigned long long)buffer_size,
                  elapsed_us(&start, &end, &frequency));

        QueryPerformanceCounter(&start);
        result = AMSI_RESULT_CLEAN;
        hr = AmsiScanBuffer(
            ctx, (PVOID)buffer, buffer_size,
            L"validation-buffer", NULL, &result);
        QueryPerformanceCounter(&end);

        observe_path(&buffer_nosession, result, hr);
        emit_scan(13 + ((round - 1) * 4),
                  "AmsiScanBuffer", "no_session", input_mode,
                  result, hr,
                  (unsigned long long)buffer_size,
                  elapsed_us(&start, &end, &frequency));
    }

    {
        HRESULT notify_hr = AmsiNotifyOperation(
            ctx,
            NULL,
            L"EDDRR-Evasion1_AMSI_Operation",
            external_path
                ? L"external-validation-operation"
                : L"benign-test-operation");

        char d[640];
        snprintf(d, sizeof(d),
                 "{\"notify_hresult\":\"0x%08lX\","
                 "\"notify_success\":%s,\"input\":\"%s\"}",
                 (unsigned long)notify_hr,
                 SUCCEEDED(notify_hr) ? "true" : "false",
                 input_mode);

        adv_emit(id, 100, "AmsiNotifyOperation",
                 "AMSI_MULTIPATH_VALIDATION", d);
    }

    {
        unsigned int total_changes =
            string_session.result_changes +
            string_nosession.result_changes +
            buffer_session.result_changes +
            buffer_nosession.result_changes;

        unsigned int total_failures =
            string_session.hr_failures +
            string_nosession.hr_failures +
            buffer_session.hr_failures +
            buffer_nosession.hr_failures;

        char d[768];
        snprintf(d, sizeof(d),
                 "{\"repeat_count\":%u,\"path_result_changes\":%u,"
                 "\"hresult_failures\":%u,"
                 "\"string_session_first\":\"%s\","
                 "\"string_no_session_first\":\"%s\","
                 "\"buffer_session_first\":\"%s\","
                 "\"buffer_no_session_first\":\"%s\"}",
                 repeats,
                 total_changes,
                 total_failures,
                 string_session.initialized
                     ? result_name(string_session.first_result)
                     : "UNOBSERVED",
                 string_nosession.initialized
                     ? result_name(string_nosession.first_result)
                     : "UNOBSERVED",
                 buffer_session.initialized
                     ? result_name(buffer_session.first_result)
                     : "UNOBSERVED",
                 buffer_nosession.initialized
                     ? result_name(buffer_nosession.first_result)
                     : "UNOBSERVED");

        adv_emit(id, 101, "CrossPathCorrelation",
                 "AMSI_MULTIPATH_VALIDATION", d);

        snprintf(d, sizeof(d),
                 "{\"status\":\"%s\","
                 "\"interpretation\":\"%s\","
                 "\"investigate\":[\"hresult_failures\","
                 "\"repeat_result_changes\","
                 "\"unexpected_cross_path_disagreement\"]}",
                 (total_failures == 0 && total_changes == 0)
                     ? "STABLE"
                     : "ANOMALY",
                 (total_failures == 0 && total_changes == 0)
                     ? "AMSI observation paths were internally stable during this run"
                     : "AMSI observations were inconsistent or returned failures; investigate provider and system state");

        adv_emit(id, 102, "DetectionOracle",
                 "AMSI_MULTIPATH_VALIDATION", d);
    }

    exit_code = 0;

cleanup:
    if (session) AmsiCloseSession(ctx, session);
    if (ctx) AmsiUninitialize(ctx);
    if (external_buffer) HeapFree(GetProcessHeap(), 0, external_buffer);
    return exit_code;
}