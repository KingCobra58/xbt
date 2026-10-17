#pragma once
#include <sys/socket.h>
#include <string>
namespace vpn_guard {
// Convert a peer socket address into a canonical numeric IP for CIDR checks.
// IPv4-mapped IPv6 is normalized to IPv4, preventing policy bypass.
bool peer_ip(const sockaddr* address, socklen_t length, std::string& result);
}
