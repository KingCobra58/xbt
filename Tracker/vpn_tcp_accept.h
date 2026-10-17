#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
namespace vpn_guard {
// Bridge accepted TCP peers to legacy XBT's IPv4-only Cconnection.
// Accepts native IPv4 and IPv4-mapped IPv6; rejects native IPv6 safely.
bool legacy_tcp_peer(const sockaddr_storage& peer, socklen_t length, sockaddr_in& legacy);
}
