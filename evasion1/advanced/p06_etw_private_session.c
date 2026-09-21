#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <stdio.h>
#include <wchar.h>
#include "poc_common.h"
#pragma comment(lib, "advapi32.lib")

int main(void)
{
    const char *id = "A06_ETW_PRIVATE_SESSION";
    WCHAR name[] = L"EDDRR_Evasion1_Private";

    ULONG cap = sizeof(EVENT_TRACE_PROPERTIES) + 256 * sizeof(WCHAR);
    EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
    if (!props) {
        adv_error(id, 1, "ETW_PRIVATE_SESSION_INTEGRITY", "HeapAlloc");
        return 1;
    }

    props->Wnode.BufferSize = cap;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_PRIVATE_LOGGER_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((WCHAR *)((BYTE *)props + props->LoggerNameOffset), 256, name);

    TRACEHANDLE session = 0;
    ULONG rc = StartTraceW(&session, name, props);
    if (rc != ERROR_SUCCESS) {
        SetLastError(rc);
        adv_error(id, 1, "ETW_PRIVATE_SESSION_INTEGRITY", "StartTraceW");
        HeapFree(GetProcessHeap(), 0, props);
        return 1;
    }

    char d[512];
    snprintf(d, sizeof(d),
             "{\"session_name\":\"EDDRR_Evasion1_Private\","
             "\"session_handle\":\"0x%llX\",\"mode\":\"private_logger\","
             "\"owned_by_test_process\":true}",
             (unsigned long long)session);
    adv_emit(id, 1, "SessionStarted", "ETW_PRIVATE_SESSION_INTEGRITY", d);

    ZeroMemory(props, cap);
    props->Wnode.BufferSize = cap;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((WCHAR *)((BYTE *)props + props->LoggerNameOffset), 256, name);

    rc = ControlTraceW(session, name, props, EVENT_TRACE_CONTROL_QUERY);
    snprintf(d, sizeof(d),
             "{\"query_result\":%lu,\"buffers_written\":%lu,"
             "\"events_lost\":%lu,\"buffers_lost\":%lu,"
             "\"log_buffers_lost\":%lu}",
             (unsigned long)rc,
             (unsigned long)props->BuffersWritten,
             (unsigned long)props->EventsLost,
             (unsigned long)props->BuffersLost,
             (unsigned long)props->LogBuffersLost);
    adv_emit(id, 2, "SessionQuery", "ETW_PRIVATE_SESSION_INTEGRITY", d);

    rc = ControlTraceW(session, name, props, EVENT_TRACE_CONTROL_STOP);
    snprintf(d, sizeof(d),
             "{\"stop_result\":%lu,\"owned_session\":true,"
             "\"external_session_modified\":false}", (unsigned long)rc);
    adv_emit(id, 3, "SessionStopped", "ETW_PRIVATE_SESSION_INTEGRITY", d);

    adv_emit(id, 4, "DetectionOracle", "ETW_PRIVATE_SESSION_INTEGRITY",
             "{\"expected_detection\":\"unexpected_ETW_session_state_change\","
             "\"baseline\":\"session_name_mode_buffers_lost_events_lost\"}");

    HeapFree(GetProcessHeap(), 0, props);
    return 0;
}
