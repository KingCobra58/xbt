#pragma once
#include "vpn_peer_identity.h"
#include <array>
#include <cstdint>
namespace vpn_guard {
// Sidecar for Ctracker_input::m_ipa. This is NOT wired to the XBT parsers.
struct announce_address {
    int family = 0;
    std::array<unsigned char, 16> bytes{};
    std::uint32_t legacy_ipv4_network = 0;
    bool has_legacy_ipv4 = false;
    std::string ip;
};
// Normalize a transport endpoint. Reject invalid address lengths/families.
bool make_announce_address(const sockaddr* source, socklen_t length, announce_address& out);
// Explicit guard for call sites which still accept only m_ipa.
bool legacy_ipv4_value(const announce_address& source, std::uint32_t& network_order);
}
