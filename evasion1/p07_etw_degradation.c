#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntprov.h>
#include <stdio.h>
#include <string.h>
#include "poc_common.h"
#pragma comment(lib, "advapi32.lib")

static const GUID LAB_PROVIDER =
{ 0x2a7e8d4b, 0x2e1d, 0x45cc, { 0x9a, 0x15, 0x7c, 0x3b, 0x4f, 0x21, 0x6d, 0x11 } };

static REGHANDLE g_reg;

static int write_sequence(unsigned long sequence, const char *state)
{
    EVENT_DATA_DESCRIPTOR data[2];
    EventDataDescCreate(&data[0], &sequence, sizeof(sequence));
    EventDataDescCreate(&data[1], state, (ULONG)(strlen(state) + 1));

    EVENT_DESCRIPTOR desc = {0};
    desc.Id = 1;
    desc.Version = 1;
    desc.Level = TRACE_LEVEL_INFORMATION;
    desc.Opcode = EVENT_TRACE_TYPE_INFO;

    ULONG rc = EventWrite(g_reg, &desc, 2, data);
    return rc == ERROR_SUCCESS;
}

int main(void)
{
    const char *poc = "P07_ETW_DEGRADATION";
    unsigned long seq = 1;

    ULONG rc = EventRegister(&LAB_PROVIDER, NULL, NULL, &g_reg);
    if (rc != ERROR_SUCCESS) {
        SetLastError(rc);
        poc_emit_error(poc, seq++, "ETW_TELEMETRY_INTEGRITY", "EventRegister");
        return 1;
    }

    poc_emit(poc, seq++, "ProviderRegistered", "ETW_TELEMETRY_INTEGRITY",
             "{\"provider\":\"EDDRR-LAB-TEST\",\"provider_guid\":\"2A7E8D4B-2E1D-45CC-9A15-7C3B4F216D11\","
             "\"telemetry_control\":\"external\",\"disable_attempt\":false}");

    if (!write_sequence(100, "continuous")) {
        poc_emit_error(poc, seq++, "ETW_TELEMETRY_INTEGRITY", "EventWrite-100");
        EventUnregister(g_reg);
        return 1;
    }
    poc_emit(poc, seq++, "EtwWrite", "ETW_TELEMETRY_INTEGRITY",
             "{\"provider_sequence\":100,\"state\":\"continuous\",\"actual_etw_write\":true}");

    /* Deliberate data-level gap. The ETW provider remains enabled. */
    if (!write_sequence(103, "fixture_gap_after_100")) {
        poc_emit_error(poc, seq++, "ETW_TELEMETRY_INTEGRITY", "EventWrite-103");
        EventUnregister(g_reg);
        return 1;
    }
    poc_emit(poc, seq++, "EtwWrite", "ETW_TELEMETRY_INTEGRITY",
             "{\"provider_sequence\":103,\"state\":\"fixture_gap_after_100\",\"skipped_sequences\":2,"
             "\"actual_etw_write\":true,\"provider_disabled\":false}");

    if (!write_sequence(104, "resumed")) {
        poc_emit_error(poc, seq++, "ETW_TELEMETRY_INTEGRITY", "EventWrite-104");
        EventUnregister(g_reg);
        return 1;
    }
    poc_emit(poc, seq++, "EtwWrite", "ETW_TELEMETRY_INTEGRITY",
             "{\"provider_sequence\":104,\"state\":\"resumed\",\"actual_etw_write\":true}");

    EventUnregister(g_reg);

    poc_emit(poc, seq++, "DetectionOracle", "ETW_TELEMETRY_INTEGRITY",
             "{\"expected_detection\":\"unexpected_sequence_discontinuity\","
             "\"gap\":[101,102],\"provider_was_disabled\":false,"
             "\"detector_action\":\"raise_telemetry_integrity_signal\"}");

    return 0;
}
