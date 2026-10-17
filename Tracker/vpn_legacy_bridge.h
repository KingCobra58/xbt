#pragma once
#include "vpn_peer_identity.h"
#include <cstdint>
namespace vpn_guard {
// Legacy XBT m_ipa is an IPv4 address in network byte order.
// Never cast an IPv6 endpoint to a 32-bit SQL/peer-map address.
bool legacy_ipv4_identity(std::uint32_t network_ip, std::uint16_t network_port, peer_identity& out);
bool legacy_ipv4_key(const peer_identity& peer, std::uint32_t& network_ip, std::uint16_t& network_port);
}
