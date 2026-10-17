#pragma once
#include "vpn_announce_ingress.h"
namespace vpn_guard {
enum class handler_route { reject_invalid, legacy_ipv4, defer_native_ipv6 };
struct handler_decision {
    handler_route route = handler_route::reject_invalid;
    std::uint32_t legacy_ipv4_network = 0;
    announce_address address{};
};
// Handler-facing safety gate. Does NOT enable IPv6 announces or VPN enforcement.
handler_decision route_announce_endpoint(announce_transport transport,
                                         const sockaddr* endpoint, socklen_t length);
}
