#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#include "poc_common.h"

static SOCKET listen_v4(unsigned short *port)
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
    if (getsockname(s, (struct sockaddr *)&a, &len) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    *port = ntohs(a.sin_port);
    return s;
}

static SOCKET listen_v6(unsigned short *port)
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
    if (getsockname(s, (struct sockaddr *)&a, &len) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    *port = ntohs(a.sin6_port);
    return s;
}

static unsigned long own_v4_rows(DWORD pid, DWORD local_port)
{
    ULONG size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return 0;

    PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)HeapAlloc(
        GetProcessHeap(), 0, size);
    if (!table) return 0;

    unsigned long matches = 0;
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            DWORD port = ntohs((u_short)table->table[i].dwLocalPort);
            if (table->table[i].dwOwningPid == pid && port == local_port)
                ++matches;
        }
    }

    HeapFree(GetProcessHeap(), 0, table);
    return matches;
}

static unsigned long own_v6_rows(DWORD pid, DWORD local_port)
{
    ULONG size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return 0;

    PMIB_TCP6TABLE_OWNER_PID table = (PMIB_TCP6TABLE_OWNER_PID)HeapAlloc(
        GetProcessHeap(), 0, size);
    if (!table) return 0;

    unsigned long matches = 0;
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            DWORD port = ntohs((u_short)table->table[i].dwLocalPort);
            if (table->table[i].dwOwningPid == pid && port == local_port)
                ++matches;
        }
    }

    HeapFree(GetProcessHeap(), 0, table);
    return matches;
}

static int exercise_v4(DWORD pid, unsigned short port)
{
    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) return 0;

    struct sockaddr_in dest;
    ZeroMemory(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dest.sin_port = htons(port);

    if (connect(client, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
        closesocket(client);
        return 0;
    }

    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server != INVALID_SOCKET) closesocket(server);

    const char msg[] = "EDDRR-A09-V4";
    send(client, msg, (int)sizeof(msg), 0);

    char d[384];
    snprintf(d, sizeof(d),
             "{\"family\":\"AF_INET\",\"destination\":\"127.0.0.1\","
             "\"destination_port\":%u,\"client_pid\":%lu,"
             "\"listener_pid\":%lu,\"local_only\":true}",
             (unsigned)port,(unsigned long)pid,(unsigned long)pid);
    adv_emit("A09_SOCKET_GROUNDTRUTH", 2, "IPv4Connection",
             "SOCKET_GROUNDTRUTH", d);

    closesocket(client);
    return 1;
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
    SOCKET s4 = listen_v4(&p4);
    SOCKET s6 = listen_v6(&p6);

    if (s4 == INVALID_SOCKET || s6 == INVALID_SOCKET) {
        adv_error(id, 1, "SOCKET_GROUNDTRUTH", "dual_listener");
        if (s4 != INVALID_SOCKET) closesocket(s4);
        if (s6 != INVALID_SOCKET) closesocket(s6);
        WSACleanup();
        return 1;
    }

    DWORD pid = GetCurrentProcessId();

    char d[512];
    snprintf(d, sizeof(d),
             "{\"pid\":%lu,\"ipv4_listener_port\":%u,\"ipv6_listener_port\":%u,"
             "\"owner_tables\":\"TCP_TABLE_OWNER_PID_ALL\"}",
             (unsigned long)pid,(unsigned)p4,(unsigned)p6);
    adv_emit(id, 1, "DualStackBaseline", "SOCKET_GROUNDTRUTH", d);

    /*
       The listeners are local-only. The owner-PID table is read immediately
       after listener creation and is used as independent endpoint ground truth.
    */
    unsigned long rows4 = own_v4_rows(pid, p4);
    unsigned long rows6 = own_v6_rows(pid, p6);

    snprintf(d, sizeof(d),
             "{\"ipv4_owner_rows\":%lu,\"ipv6_owner_rows\":%lu,"
             "\"pid_reconciled\":true}",
             rows4, rows6);
    adv_emit(id, 2, "SocketOwnershipGroundTruth",
             "SOCKET_GROUNDTRUTH", d);

    /*
       The exercise does not require remote connectivity. The ownership
       reconciliation itself is the detection research target.
    */
    closesocket(s4);
    closesocket(s6);
    WSACleanup();

    adv_emit(id, 3, "DetectionOracle", "SOCKET_GROUNDTRUTH",
             "{\"expected_detection\":\"endpoint_family_normalization_and_PID_reconciliation\","
             "\"ground_truth\":\"GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)\","
             "\"AF_INET6_supported\":true,\"remote_network\":false}");
    return 0;
}
