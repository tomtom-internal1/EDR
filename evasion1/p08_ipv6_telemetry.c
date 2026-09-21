#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#include "poc_common.h"

static int make_listener(SOCKET *out, unsigned short *port)
{
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    struct sockaddr_in6 a;
    ZeroMemory(&a, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_addr = in6addr_loopback;
    a.sin6_port = 0;

    if (bind(s, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR ||
        listen(s, 1) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }

    int len = sizeof(a);
    if (getsockname(s, (struct sockaddr *)&a, &len) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }

    *out = s;
    *port = ntohs(a.sin6_port);
    return 1;
}

int main(void)
{
    const char *poc = "P08_IPV6_TELEMETRY";
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        poc_emit_error(poc, 1, "IPV6_NETWORK_TELEMETRY", "WSAStartup");
        return 1;
    }

    SOCKET listener;
    unsigned short port;
    if (!make_listener(&listener, &port)) {
        poc_emit_error(poc, 1, "IPV6_NETWORK_TELEMETRY", "IPv6_listener");
        WSACleanup();
        return 1;
    }

    char details[384];
    snprintf(details, sizeof(details),
             "{\"family\":\"AF_INET6\",\"local_address\":\"::1\",\"port\":%u,"
             "\"scope\":\"loopback\",\"remote_network\":false}",
             (unsigned)port);
    poc_emit(poc, 1, "Listen", "IPV6_NETWORK_TELEMETRY", details);

    SOCKET client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        poc_emit_error(poc, 2, "IPV6_NETWORK_TELEMETRY", "client_socket");
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    struct sockaddr_in6 dest;
    ZeroMemory(&dest, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_addr = in6addr_loopback;
    dest.sin6_port = htons(port);

    if (connect(client, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
        poc_emit_error(poc, 2, "IPV6_NETWORK_TELEMETRY", "connect(::1)");
        closesocket(client);
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    SOCKET accepted = accept(listener, NULL, NULL);
    if (accepted == INVALID_SOCKET) {
        poc_emit_error(poc, 3, "IPV6_NETWORK_TELEMETRY", "accept");
        closesocket(client);
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    const char marker[] = "EDDRR-IPV6-LOCAL";
    send(client, marker, (int)sizeof(marker), 0);

    char received[64] = {0};
    recv(accepted, received, sizeof(received) - 1, 0);

    const char reply[] = "EDDRR-IPV6-ACK";
    send(accepted, reply, (int)sizeof(reply), 0);

    char client_reply[64] = {0};
    recv(client, client_reply, sizeof(client_reply) - 1, 0);

    poc_emit(poc, 2, "Connection", "IPV6_NETWORK_TELEMETRY",
             "{\"family\":\"AF_INET6\",\"source\":\"::1\",\"destination\":\"::1\","
             "\"protocol\":\"TCP\",\"local_only\":true,\"remote_address\":false,"
             "\"application_data\":\"benign_marker_roundtrip\"}");

    closesocket(accepted);
    closesocket(client);
    closesocket(listener);
    WSACleanup();

    poc_emit(poc, 3, "ConnectionClose", "IPV6_NETWORK_TELEMETRY",
             "{\"family\":\"AF_INET6\",\"lifecycle_complete\":true}");

    poc_emit(poc, 4, "DetectionOracle", "IPV6_NETWORK_TELEMETRY",
             "{\"expected_detection\":\"address_family_normalization\","
             "\"rule\":\"AF_INET6_and_AF_INET_share_endpoint_schema\","
             "\"loopback_exception\":\"classify_as_local\",\"this_flow_expected_benign\":true}");

    return 0;
}
