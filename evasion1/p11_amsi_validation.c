#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "amsi.lib")
#include "poc_common.h"

static const char *result_name(AMSI_RESULT result)
{
    if (result == AMSI_RESULT_CLEAN) return "CLEAN";
    if (result == AMSI_RESULT_NOT_DETECTED) return "NOT_DETECTED";
    if (result >= AMSI_RESULT_DETECTED) return "DETECTED";
    return "OTHER";
}

static int is_blocking_result(AMSI_RESULT result)
{
    return result >= AMSI_RESULT_DETECTED;
}

int main(void)
{
    const char *poc = "P11_AMSI_VALIDATION";
    unsigned long seq = 1;
    HAMSICONTEXT context = NULL;
    HAMSISESSION session = NULL;

    HRESULT hr = AmsiInitialize(L"EDDRR-Evasion1-AMSI-Test", &context);
    if (FAILED(hr)) {
        SetLastError((DWORD)hr);
        poc_emit_error(poc, seq++, "AMSI_VALIDATION", "AmsiInitialize");
        return 1;
    }

    poc_emit(poc, seq++, "AmsiInitialize", "AMSI_VALIDATION",
             "{\"application\":\"EDDRR-Evasion1-AMSI-Test\",\"status\":\"success\"}");

    hr = AmsiOpenSession(context, &session);
    if (FAILED(hr)) {
        SetLastError((DWORD)hr);
        poc_emit_error(poc, seq++, "AMSI_VALIDATION", "AmsiOpenSession");
        AmsiUninitialize(context);
        return 1;
    }

    poc_emit(poc, seq++, "AmsiOpenSession", "AMSI_VALIDATION",
             "{\"session_created\":true,\"correlation\":\"single_session\"}");

    const char *test =
        "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";

    AMSI_RESULT result = AMSI_RESULT_CLEAN;
    hr = AmsiScanBuffer(context,
                        (PVOID)test,
                        (ULONG)strlen(test),
                        L"EDDRR-Evasion1-AMSI-Test",
                        session,
                        &result);

    char details[512];
    snprintf(details, sizeof(details),
             "{\"hresult\":\"0x%08lX\",\"amsi_result\":%lu,"
             "\"amsi_result_name\":\"%s\",\"blocking_result\":%s}",
             (unsigned long)hr,
             (unsigned long)result,
             result_name(result),
             is_blocking_result(result) ? "true" : "false");
    poc_emit(poc, seq++, "AmsiScanBuffer", "AMSI_VALIDATION", details);

    if (FAILED(hr)) {
        poc_emit(poc, seq++, "DetectionOracle", "AMSI_VALIDATION",
                 "{\"state\":\"AMSI_SCAN_ERROR\",\"action\":\"inspect_provider_health\"}");
    } else if (result == AMSI_RESULT_CLEAN) {
        poc_emit(poc, seq++, "DetectionOracle", "AMSI_VALIDATION",
                 "{\"state\":\"AMSI_INTEGRITY_ANOMALY\","
                 "\"reason\":\"validation_sample_returned_clean\","
                 "\"action\":\"inspect_provider_health_and_integrity\","
                 "\"not_proof_of_specific_bypass\":true}");
    } else {
        poc_emit(poc, seq++, "DetectionOracle", "AMSI_VALIDATION",
                 "{\"state\":\"AMSI_ACTIVE\","
                 "\"reason\":\"validation_sample_was_not_returned_clean\","
                 "\"action\":\"record_baseline\"}");
    }

    AmsiCloseSession(context, session);
    AmsiUninitialize(context);

    poc_emit(poc, seq++, "AmsiCleanup", "AMSI_VALIDATION",
             "{\"context_released\":true,\"memory_patch_performed\":false,"
             "\"provider_disabled\":false}");
    return 0;
}
