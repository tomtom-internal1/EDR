#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#include "poc_common.h"

static unsigned long count_v4(DWORD pid)
{
    ULONG size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_LISTENER, 0) != ERROR_INSUFFICIENT_BUFFER)
        return 0;
    PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)HeapAlloc(
        GetProcessHeap(), 0, size);
    if (!table) return 0;

    unsigned long count = 0;
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_LISTENER, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i)
            if (table->table[i].dwOwningPid == pid) ++count;
    }
    HeapFree(GetProcessHeap(), 0, table);
    return count;
}

static unsigned long count_v6(DWORD pid)
{
    ULONG size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_LISTENER, 0) != ERROR_INSUFFICIENT_BUFFER)
        return 0;
    PMIB_TCP6TABLE_OWNER_PID table = (PMIB_TCP6TABLE_OWNER_PID)HeapAlloc(
        GetProcessHeap(), 0, size);
    if (!table) return 0;

    unsigned long count = 0;
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_LISTENER, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i)
            if (table->table[i].dwOwningPid == pid) ++count;
    }
    HeapFree(GetProcessHeap(), 0, table);
    return count;
}

static SOCKET listen4(unsigned short *port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in a;
    ZeroMemory(&a, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;

    if (bind(s, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR ||
        listen(s, 1) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    int len = sizeof(a);
    getsockname(s, (struct sockaddr *)&a, &len);
    *port = ntohs(a.sin_port);
    return s;
}

static SOCKET listen6(unsigned short *port)
{
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in6 a;
    ZeroMemory(&a, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_addr = in6addr_loopback;
    a.sin6_port = 0;

    if (bind(s, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR ||
        listen(s, 1) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    int len = sizeof(a);
    getsockname(s, (struct sockaddr *)&a, &len);
    *port = ntohs(a.sin6_port);
    return s;
}

int main(void)
{
    const char *id = "A09_SOCKET_GROUNDTRUTH";
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        adv_error(id, 1, "SOCKET_GROUNDTRUTH", "WSAStartup");
        return 1;
    }

    unsigned short p4 = 0, p6 = 0;
    SOCKET s4 = listen4(&p4);
    SOCKET s6 = listen6(&p6);

    if (s4 == INVALID_SOCKET || s6 == INVALID_SOCKET) {
        adv_error(id, 1, "SOCKET_GROUNDTRUTH", "dual_listener");
        if (s4 != INVALID_SOCKET) closesocket(s4);
        if (s6 != INVALID_SOCKET) closesocket(s6);
        WSACleanup();
        return 1;
    }

    DWORD pid = GetCurrentProcessId();
    unsigned long c4 = count_v4(pid);
    unsigned long c6 = count_v6(pid);

    char d[384];
    snprintf(d, sizeof(d),
             "{\"pid\":%lu,\"ipv4_loopback_port\":%u,"
             "\"ipv6_loopback_port\":%u,\"ipv4_owner_pid_rows\":%lu,"
             "\"ipv6_owner_pid_rows\":%lu}",
             (unsigned long)pid, (unsigned)p4, (unsigned)p6, c4, c6);
    adv_emit(id, 1, "SocketGroundTruth", "SOCKET_GROUNDTRUTH", d);

    adv_emit(id, 2, "DetectionOracle", "SOCKET_GROUNDTRUTH",
             "{\"expected_detection\":\"endpoint_family_normalization_and_PID_reconciliation\","
             "\"ground_truth\":\"GetExtendedTcpTable\",\"remote_network\":false}");

    closesocket(s4);
    closesocket(s6);
    WSACleanup();
    return 0;
}
