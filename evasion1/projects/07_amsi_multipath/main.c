#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "amsi.lib")
#include "poc_common.h"

static const char *result_name(AMSI_RESULT r)
{
    if (r == AMSI_RESULT_CLEAN) return "CLEAN";
    if (r == AMSI_RESULT_NOT_DETECTED) return "NOT_DETECTED";
    if (r >= AMSI_RESULT_DETECTED) return "DETECTED";
    return "OTHER";
}

static void emit_scan(unsigned long seq, const char *method, AMSI_RESULT r, HRESULT hr)
{
    char d[384];
    snprintf(d, sizeof(d),
             "{\"method\":\"%s\",\"hresult\":\"0x%08lX\","
             "\"result\":%lu,\"result_name\":\"%s\","
             "\"result_is_malware\":%s}",
             method, (unsigned long)hr, (unsigned long)r, result_name(r),
             AmsiResultIsMalware(r) ? "true" : "false");
    adv_emit("A07_AMSI_MULTIPATH", seq, "AmsiScan",
             "AMSI_MULTIPATH_VALIDATION", d);
}

int main(void)
{
    const char *id = "A07_AMSI_MULTIPATH";
    HAMSICONTEXT ctx = NULL;
    HAMSISESSION session = NULL;

    HRESULT hr = AmsiInitialize(L"EDDRR-Evasion1-AMSI-Multipath", &ctx);
    if (FAILED(hr)) {
        SetLastError((DWORD)hr);
        adv_error(id, 1, "AMSI_MULTIPATH_VALIDATION", "AmsiInitialize");
        return 1;
    }

    hr = AmsiOpenSession(ctx, &session);
    if (FAILED(hr)) {
        SetLastError((DWORD)hr);
        adv_error(id, 1, "AMSI_MULTIPATH_VALIDATION", "AmsiOpenSession");
        AmsiUninitialize(ctx);
        return 1;
    }

    const wchar_t *benign = L"EDDRR-Evasion1 benign multipath validation";
    const char *sample =
        "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";

    AMSI_RESULT r1 = AMSI_RESULT_CLEAN;
    AMSI_RESULT r2 = AMSI_RESULT_CLEAN;

    hr = AmsiScanString(ctx, benign, L"benign-string", session, &r1);
    emit_scan(2, "AmsiScanString", r1, hr);

    hr = AmsiScanBuffer(ctx, (PVOID)sample, (ULONG)strlen(sample),
                        L"validation-buffer", session, &r2);
    emit_scan(3, "AmsiScanBuffer", r2, hr);

    HRESULT notify_hr = AmsiNotifyOperation(
        ctx, NULL, L"EDDRR_Evasion1_AMSI_Operation", L"benign-test-operation");

    char d[384];
    snprintf(d, sizeof(d),
             "{\"notify_hresult\":\"0x%08lX\","
             "\"buffer_result_is_malware\":%s,"
             "\"string_result_is_malware\":%s}",
             (unsigned long)notify_hr,
             AmsiResultIsMalware(r2) ? "true" : "false",
             AmsiResultIsMalware(r1) ? "true" : "false");
    adv_emit(id, 4, "CrossPathCorrelation", "AMSI_MULTIPATH_VALIDATION", d);

    adv_emit(id, 5, "DetectionOracle", "AMSI_MULTIPATH_VALIDATION",
             "{\"expected_detection\":\"inconsistent_AMSI_result_behavior\","
             "\"signals\":[\"AmsiScanString\",\"AmsiScanBuffer\",\"AmsiNotifyOperation\"],"
             "\"unexpected_clean_validation\":\"investigate_provider_health_and_integrity\"}");

    AmsiCloseSession(ctx, session);
    AmsiUninitialize(ctx);
    return 0;
}
