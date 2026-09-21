#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "poc_common.h"

int main(void)
{
    const char *poc = "P07_ETW_DEGRADATION";
    unsigned long seq = 1;
    const char *provider = "EDDRR-LAB-TEST";
    char detail[320];

    snprintf(detail, sizeof(detail),
             "{\"provider\":\"%s\",\"sequence_expected\":100,\"sequence_observed\":100,"
             "\"status\":\"continuous\",\"simulation\":true}", provider);
    poc_emit(poc, seq++, "TelemetryObserved", "ETW_TELEMETRY_INTEGRITY", detail);

    snprintf(detail, sizeof(detail),
             "{\"provider\":\"%s\",\"sequence_expected\":101,\"sequence_observed\":103,"
             "\"missing_count\":2,\"reason\":\"intentional_fixture_gap\",\"simulation\":true}", provider);
    poc_emit(poc, seq++, "TelemetryGap", "ETW_TELEMETRY_INTEGRITY", detail);

    snprintf(detail, sizeof(detail),
             "{\"provider\":\"%s\",\"sequence_expected\":104,\"sequence_observed\":104,"
             "\"status\":\"resumed\",\"simulation\":true}", provider);
    poc_emit(poc, seq++, "TelemetryObserved", "ETW_TELEMETRY_INTEGRITY", detail);

    poc_emit(poc, seq++, "DetectionOracle", "ETW_TELEMETRY_INTEGRITY",
             "{\"expected_detection\":\"telemetry_degradation\",\"do_not_treat_missing_as_benign\":true}");

    return 0;
}
