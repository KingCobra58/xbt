#pragma once
#include <sys/socket.h>
#include <string>
namespace vpn_guard {
struct peer_identity {
    sockaddr_storage address{};
    socklen_t length = 0;
    std::string ip;
    unsigned short port = 0;
    bool is_ipv6 = false;
};
// Canonical peer identity; IPv4-mapped IPv6 normalizes to IPv4.
bool make_peer_identity(const sockaddr* address, socklen_t length, peer_identity& out);
}
