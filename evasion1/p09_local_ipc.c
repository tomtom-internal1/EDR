#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "poc_common.h"

static const wchar_t *PIPE_NAME = L"\\.\pipe\EDDRR-Evasion1-P09";

static int child_mode(void)
{
    HANDLE pipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        poc_emit_error("P09_LOCAL_IPC", 1, "LOCAL_IPC", "child_OpenPipe");
        return 1;
    }

    const char message[] = "EDDRR-P09-LOCAL-IPC";
    DWORD written = 0;
    BOOL ok = WriteFile(pipe, message, (DWORD)sizeof(message), &written, NULL);

    poc_emit("P09_LOCAL_IPC", 4, "ChildPipeWrite", "LOCAL_IPC",
             ok ? "{\"role\":\"child\",\"transport\":\"named_pipe\",\"bytes_written\":20}"
                : "{\"role\":\"child\",\"transport\":\"named_pipe\",\"write\":\"failure\"}");

    CloseHandle(pipe);
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0)
        return child_mode();

    const char *poc = "P09_LOCAL_IPC";
    unsigned long seq = 1;

    HANDLE pipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 512, 512, 0, NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        poc_emit_error(poc, seq++, "LOCAL_IPC", "CreateNamedPipeW");
        return 1;
    }

    poc_emit(poc, seq++, "NamedPipeCreate", "LOCAL_IPC",
             "{\"object\":\"\\\\.\\pipe\\EDDRR-Evasion1-P09\","
             "\"scope\":\"same_host\",\"remote_network_event_expected\":false}");

    WCHAR self[MAX_PATH];
    if (!GetModuleFileNameW(NULL, self, MAX_PATH)) {
        poc_emit_error(poc, seq++, "LOCAL_IPC", "GetModuleFileNameW");
        CloseHandle(pipe);
        return 1;
    }

    WCHAR command[2 * MAX_PATH];
    _snwprintf_s(command, sizeof(command) / sizeof(command[0]), _TRUNCATE,
                 L"\"%s\" --child", self);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        poc_emit_error(poc, seq++, "LOCAL_IPC", "CreateProcessW");
        CloseHandle(pipe);
        return 1;
    }

    poc_emit(poc, seq++, "ChildProcessCreate", "LOCAL_IPC",
             "{\"transport\":\"named_pipe\",\"process_relationship\":\"same_host_child\",\"execution\":\"benign\"}");

    BOOL connected = ConnectNamedPipe(pipe, NULL);
    DWORD connect_status = connected ? ERROR_SUCCESS : GetLastError();

    if (!connected && connect_status != ERROR_PIPE_CONNECTED) {
        SetLastError(connect_status);
        poc_emit_error(poc, seq++, "LOCAL_IPC", "ConnectNamedPipe");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pipe);
        return 1;
    }

    char received[64] = {0};
    DWORD read = 0;
    BOOL read_ok = ReadFile(pipe, received, sizeof(received) - 1, &read, NULL);

    char details[384];
    snprintf(details, sizeof(details),
             "{\"server_pid\":%lu,\"client_pid\":%lu,"
             "\"transport\":\"named_pipe\",\"bytes_read\":%lu,"
             "\"message_valid\":%s,\"network_socket\":false}",
             (unsigned long)GetCurrentProcessId(),
             (unsigned long)pi.dwProcessId,
             (unsigned long)read,
             (read_ok && strcmp(received, "EDDRR-P09-LOCAL-IPC") == 0) ? "true" : "false");
    poc_emit(poc, seq++, "PipeTransfer", "LOCAL_IPC", details);

    WaitForSingleObject(pi.hProcess, 3000);
    DWORD child_exit = 1;
    GetExitCodeProcess(pi.hProcess, &child_exit);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);

    HKEY key = NULL;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER,
                              L"Software\\EDDRR\\Evasion1\\P09",
                              0, NULL, 0, KEY_READ | KEY_WRITE, NULL,
                              &key, NULL);
    if (rc != ERROR_SUCCESS) {
        poc_emit_error(poc, seq++, "LOCAL_IPC", "RegCreateKeyExW");
        return 1;
    }

    const wchar_t value[] = L"EDDRR-P09-REGISTRY-IPC";
    rc = RegSetValueExW(key, L"Message", 0, REG_SZ,
                        (const BYTE *)value,
                        (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));

    DWORD type = 0;
    DWORD cb = 0;
    RegQueryValueExW(key, L"Message", NULL, &type, NULL, &cb);

    char reg_detail[320];
    snprintf(reg_detail, sizeof(reg_detail),
             "{\"operation\":\"registry_roundtrip\",\"scope\":\"HKCU\","
             "\"write_result\":%ld,\"value_type\":%lu,\"value_bytes\":%lu}",
             (long)rc, (unsigned long)type, (unsigned long)cb);
    poc_emit(poc, seq++, "RegistryIpc", "LOCAL_IPC", reg_detail);

    RegCloseKey(key);

    HKEY cleanup = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\EDDRR\\Evasion1\\P09",
                      0, KEY_WRITE, &cleanup) == ERROR_SUCCESS) {
        RegDeleteValueW(cleanup, L"Message");
        RegCloseKey(cleanup);
    }

    HKEY parent = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\EDDRR\\Evasion1",
                      0, KEY_WRITE, &parent) == ERROR_SUCCESS) {
        RegDeleteKeyW(parent, L"P09");
        RegCloseKey(parent);
    }

    snprintf(reg_detail, sizeof(reg_detail),
             "{\"cleanup\":true,\"child_exit_code\":%lu,"
             "\"named_pipe_and_registry\":\"same_host_ipc_paths\"}",
             (unsigned long)child_exit);
    poc_emit(poc, seq++, "IpcLifecycleEnd", "LOCAL_IPC", reg_detail);

    poc_emit(poc, seq++, "DetectionOracle", "LOCAL_IPC",
             "{\"expected_detection\":\"cross_process_local_communication\","
             "\"correlate\":[\"ChildProcessCreate\",\"PipeTransfer\",\"RegistryIpc\"],"
             "\"network_visibility_not_required\":true}");

    return 0;
}
