#pragma once
#include "vpn_peer_identity.h"
#include <string>
namespace vpn_guard {
// Append one peer in BEP 23 compact binary form (IPv4: 6 bytes; IPv6: 18).
// IPv4-mapped IPv6 addresses are emitted as IPv4. Ports are network-order.
bool append_compact_peer(const peer_identity& peer, std::string& peers4, std::string& peers6);
// Compose announce response with both compact address families (BEP 7 peers6).
std::string compact_announce_response(unsigned complete, unsigned incomplete, unsigned interval,
                                     const std::string& peers4, const std::string& peers6);
}
