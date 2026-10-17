#include "vpn_peer_identity.h"
#include "vpn_socket_address.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
namespace vpn_guard {
bool make_peer_identity(const sockaddr* address, socklen_t length, peer_identity& out) {
    out = peer_identity{};
    if (!address || length > sizeof(sockaddr_storage)) return false;
    if (address->sa_family != AF_INET && address->sa_family != AF_INET6) return false;
    if (length < (address->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6))) return false;
    if (!peer_ip(address, length, out.ip)) return false;
    std::memcpy(&out.address, address, length);
    out.length = length;
    if (address->sa_family == AF_INET) {
        out.port = ntohs(reinterpret_cast<const sockaddr_in*>(address)->sin_port);
    } else {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
        out.port = ntohs(v6->sin6_port);
        out.is_ipv6 = !IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr);
    }
    return true;
}
}
