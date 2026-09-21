#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <stdio.h>
#include <wchar.h>
#include "poc_common.h"
#pragma comment(lib, "advapi32.lib")

static void init_props(EVENT_TRACE_PROPERTIES *p, ULONG cap, WCHAR *name)
{
    ZeroMemory(p, cap);
    p->Wnode.BufferSize = cap;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;
    p->LogFileMode = EVENT_TRACE_PRIVATE_LOGGER_MODE;
    p->MinimumBuffers = 2;
    p->MaximumBuffers = 8;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((WCHAR *)((BYTE *)p + p->LoggerNameOffset), 256, name);
}

int main(void)
{
    const char *id = "A06_ETW_PRIVATE_SESSION";
    WCHAR name[] = L"EDDRR_Evasion1_Private";

    ULONG cap = sizeof(EVENT_TRACE_PROPERTIES) + 256 * sizeof(WCHAR);
    EVENT_TRACE_PROPERTIES *props =
        (EVENT_TRACE_PROPERTIES *)HeapAlloc(GetProcessHeap(),
                                             HEAP_ZERO_MEMORY, cap);
    if (!props) {
        adv_error(id, 1, "ETW_PRIVATE_SESSION_INTEGRITY", "HeapAlloc");
        return 1;
    }

    init_props(props, cap, name);

    TRACEHANDLE session = 0;
    ULONG rc = StartTraceW(&session, name, props);
    if (rc != ERROR_SUCCESS) {
        SetLastError(rc);
        adv_error(id, 1, "ETW_PRIVATE_SESSION_INTEGRITY", "StartTraceW");
        HeapFree(GetProcessHeap(), 0, props);
        return 1;
    }

    char d[640];
    snprintf(d, sizeof(d),
             "{\"session_name\":\"EDDRR_Evasion1_Private\","
             "\"session_handle\":\"0x%llX\","
             "\"mode\":\"private_logger\","
             "\"minimum_buffers\":%lu,\"maximum_buffers\":%lu}",
             (unsigned long long)session,
             (unsigned long)props->MinimumBuffers,
             (unsigned long)props->MaximumBuffers);
    adv_emit(id, 1, "SessionStarted",
             "ETW_PRIVATE_SESSION_INTEGRITY", d);

    ZeroMemory(props, cap);
    props->Wnode.BufferSize = cap;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((WCHAR *)((BYTE *)props + props->LoggerNameOffset), 256, name);

    rc = ControlTraceW(session, name, props, EVENT_TRACE_CONTROL_QUERY);

    snprintf(d, sizeof(d),
             "{\"query_result\":%lu,"
             "\"buffers_written\":%lu,"
             "\"events_lost\":%lu,"
             "\"log_buffers_lost\":%lu,"
             "\"real_time_buffers_lost\":%lu,"
             "\"number_of_buffers\":%lu}",
             (unsigned long)rc,
             (unsigned long)props->BuffersWritten,
             (unsigned long)props->EventsLost,
             (unsigned long)props->LogBuffersLost,
             (unsigned long)props->RealTimeBuffersLost,
             (unsigned long)props->NumberOfBuffers);
    adv_emit(id, 2, "SessionQuery",
             "ETW_PRIVATE_SESSION_INTEGRITY", d);

    ULONG stop_rc = ControlTraceW(session, name, props,
                                  EVENT_TRACE_CONTROL_STOP);

    snprintf(d, sizeof(d),
             "{\"stop_result\":%lu,\"owned_session\":true,"
             "\"external_session_modified\":false}",
             (unsigned long)stop_rc);
    adv_emit(id, 3, "SessionStopped",
             "ETW_PRIVATE_SESSION_INTEGRITY", d);

    adv_emit(id, 4, "DetectionOracle",
             "ETW_PRIVATE_SESSION_INTEGRITY",
             "{\"expected_detection\":\"unexpected_ETW_session_state_change\","
             "\"baseline\":\"session_name_mode_buffer_counts_loss_counters\"}");

    HeapFree(GetProcessHeap(), 0, props);
    return stop_rc == ERROR_SUCCESS ? 0 : 2;
}
