#include "vpn_legacy_bridge.h"
#include <arpa/inet.h>
#include <cstring>
namespace vpn_guard {
bool legacy_ipv4_identity(std::uint32_t ip, std::uint16_t port, peer_identity& out) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = ip;
    a.sin_port = port;
    return make_peer_identity(reinterpret_cast<const sockaddr*>(&a), sizeof(a), out);
}
bool legacy_ipv4_key(const peer_identity& peer, std::uint32_t& ip, std::uint16_t& port) {
    if (peer.is_ipv6 || peer.length < sizeof(sockaddr_in)) return false;
    // Identity may have originated as IPv4-mapped IPv6: convert its canonical text.
    in_addr a{};
    if (inet_pton(AF_INET, peer.ip.c_str(), &a) != 1) return false;
    ip = a.s_addr;
    port = htons(peer.port);
    return true;
}
}
