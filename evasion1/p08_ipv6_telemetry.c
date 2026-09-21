#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#include "poc_common.h"

typedef struct {
    SOCKET listener;
} SERVER_CONTEXT;

static DWORD WINAPI server_thread(LPVOID param)
{
    SERVER_CONTEXT *ctx = (SERVER_CONTEXT *)param;
    struct sockaddr_in6 peer;
    int peer_len = sizeof(peer);
    SOCKET client = accept(ctx->listener, (struct sockaddr *)&peer, &peer_len);
    if (client == INVALID_SOCKET) return 1;

    char buffer[64] = {0};
    recv(client, buffer, sizeof(buffer) - 1, 0);
    send(client, "EDDRR-IPV6-OK", 14, 0);

    closesocket(client);
    return 0;
}

int main(void)
{
    const char *poc = "P08_IPV6_TELEMETRY";
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        poc_emit_error(poc, 1, "IPV6_NETWORK_TELEMETRY", "WSAStartup");
        return 1;
    }

    SOCKET listener = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        poc_emit_error(poc, 1, "IPV6_NETWORK_TELEMETRY", "socket(AF_INET6)");
        WSACleanup();
        return 1;
    }

    struct sockaddr_in6 addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_loopback;
    addr.sin6_port = 0;

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(listener, 1) == SOCKET_ERROR) {
        poc_emit_error(poc, 1, "IPV6_NETWORK_TELEMETRY", "bind/listen");
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    int addr_len = sizeof(addr);
    getsockname(listener, (struct sockaddr *)&addr, &addr_len);

    char details[320];
    snprintf(details, sizeof(details),
             "{\"address_family\":\"AF_INET6\",\"destination\":\"::1\","
             "\"port\":%u,\"scope\":\"loopback\",\"remote_network\":false}",
             (unsigned)ntohs(addr.sin6_port));
    poc_emit(poc, 1, "Listen", "IPV6_NETWORK_TELEMETRY", details);

    SERVER_CONTEXT ctx = { listener };
    HANDLE thread = CreateThread(NULL, 0, server_thread, &ctx, 0, NULL);
    if (!thread) {
        poc_emit_error(poc, 2, "IPV6_NETWORK_TELEMETRY", "CreateThread");
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    SOCKET client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        poc_emit_error(poc, 2, "IPV6_NETWORK_TELEMETRY", "client_socket");
        WaitForSingleObject(thread, 2000);
        CloseHandle(thread);
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        poc_emit_error(poc, 2, "IPV6_NETWORK_TELEMETRY", "connect(::1)");
        closesocket(client);
        WaitForSingleObject(thread, 2000);
        CloseHandle(thread);
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    send(client, "EDDRR-LOCAL-IPV6", 16, 0);
    char reply[32] = {0};
    recv(client, reply, sizeof(reply) - 1, 0);

    poc_emit(poc, 2, "Connection", "IPV6_NETWORK_TELEMETRY",
             "{\"address_family\":\"AF_INET6\",\"destination\":\"::1\","
             "\"protocol\":\"TCP\",\"purpose\":\"local telemetry fixture\"}");

    closesocket(client);
    WaitForSingleObject(thread, 2000);
    CloseHandle(thread);
    closesocket(listener);
    WSACleanup();

    poc_emit(poc, 3, "ConnectionClose", "IPV6_NETWORK_TELEMETRY",
             "{\"loopback_only\":true,\"remote_connection\":false}");

    return 0;
}
