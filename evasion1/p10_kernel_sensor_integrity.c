#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "poc_common.h"

static unsigned long count_threads_for_pid(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    ZeroMemory(&te, sizeof(te));
    te.dwSize = sizeof(te);

    unsigned long count = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                ++count;
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return count;
}

static int module_present(const wchar_t *needle)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                           GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me;
    ZeroMemory(&me, sizeof(me));
    me.dwSize = sizeof(me);

    int found = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, needle) == 0) {
                found = 1;
                break;
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return found;
}

typedef struct {
    HANDLE ready;
    HANDLE done;
} WORK;

static DWORD WINAPI short_worker(LPVOID p)
{
    WORK *w = (WORK *)p;
    SetEvent(w->ready);
    Sleep(250);
    SetEvent(w->done);
    return 0;
}

int main(void)
{
    const char *poc = "P10_KERNEL_SENSOR_INTEGRITY";
    DWORD pid = GetCurrentProcessId();
    unsigned long seq = 1;

    unsigned long baseline_threads = count_threads_for_pid(pid);
    int kernel32_present = module_present(L"kernel32.dll");

    char detail[512];
    snprintf(detail, sizeof(detail),
             "{\"ground_truth_source\":\"Toolhelp32\",\"pid\":%lu,"
             "\"thread_count\":%lu,\"kernel32_present\":%s,"
             "\"sensor_mutation\":false}",
             (unsigned long)pid, baseline_threads,
             kernel32_present ? "true" : "false");
    poc_emit(poc, seq++, "GroundTruthBaseline", "KERNEL_SENSOR_INTEGRITY", detail);

    WORK w = { CreateEventW(NULL, TRUE, FALSE, NULL),
               CreateEventW(NULL, TRUE, FALSE, NULL) };
    if (!w.ready || !w.done) {
        poc_emit_error(poc, seq++, "KERNEL_SENSOR_INTEGRITY", "CreateEvent");
        return 1;
    }

    HANDLE worker = CreateThread(NULL, 0, short_worker, &w, 0, NULL);
    if (!worker) {
        poc_emit_error(poc, seq++, "KERNEL_SENSOR_INTEGRITY", "CreateThread");
        CloseHandle(w.ready);
        CloseHandle(w.done);
        return 1;
    }

    WaitForSingleObject(w.ready, INFINITE);
    unsigned long during_threads = count_threads_for_pid(pid);

    snprintf(detail, sizeof(detail),
             "{\"ground_truth_source\":\"Toolhelp32\",\"pid\":%lu,"
             "\"thread_count_during_worker\":%lu,\"worker_tid\":%lu}",
             (unsigned long)pid, during_threads,
             (unsigned long)GetThreadId(worker));
    poc_emit(poc, seq++, "GroundTruthThreadChange", "KERNEL_SENSOR_INTEGRITY", detail);

    /* Deliberate mirror-channel loss. No kernel callback is altered. */
    poc_emit(poc, seq++, "SensorMirrorObservation", "KERNEL_SENSOR_INTEGRITY",
             "{\"event_class\":\"thread_create\",\"observed\":false,"
             "\"ground_truth\":true,\"loss_mode\":\"simulated_mirror_gap\"}");

    WaitForSingleObject(w.done, 1000);
    WaitForSingleObject(worker, 1000);

    unsigned long final_threads = count_threads_for_pid(pid);
    snprintf(detail, sizeof(detail),
             "{\"ground_truth_final_threads\":%lu,\"worker_completed\":true,"
             "\"kernel_callback_table_modified\":false}",
             final_threads);
    poc_emit(poc, seq++, "GroundTruthRecovery", "KERNEL_SENSOR_INTEGRITY", detail);

    CloseHandle(worker);
    CloseHandle(w.ready);
    CloseHandle(w.done);

    poc_emit(poc, seq++, "DetectionOracle", "KERNEL_SENSOR_INTEGRITY",
             "{\"expected_detection\":\"source_specific_visibility_gap\","
             "\"independent_ground_truth\":\"Toolhelp32\","
             "\"do_not_claim_kernel_tampering\":true}");

    return 0;
}
