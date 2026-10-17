#include "vpn_announce_address.h"
#include <arpa/inet.h>
#include <cstring>
namespace vpn_guard {
bool make_announce_address(const sockaddr* source, socklen_t length, announce_address& out) {
    out = announce_address{};
    peer_identity identity;
    if (!make_peer_identity(source, length, identity)) return false;
    out.ip = identity.ip;
    out.family = identity.is_ipv6 ? AF_INET6 : AF_INET;
    if (inet_pton(out.family, out.ip.c_str(), out.bytes.data()) != 1) {
        out = announce_address{};
        return false;
    }
    if (out.family == AF_INET) {
        std::memcpy(&out.legacy_ipv4_network, out.bytes.data(), 4);
        out.has_legacy_ipv4 = true;
    }
    return true;
}
bool legacy_ipv4_value(const announce_address& source, std::uint32_t& network_order) {
    if (source.family != AF_INET || !source.has_legacy_ipv4) return false;
    network_order = source.legacy_ipv4_network;
    return true;
}
}
