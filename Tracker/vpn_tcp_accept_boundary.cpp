#include "vpn_tcp_accept_boundary.h"
#include <cstring>
namespace vpn_guard {
tcp_accept_result prepare_tcp_accept(const sockaddr* endpoint, socklen_t length) {
    tcp_accept_result result{};
    const auto decision = route_announce_endpoint(announce_transport::tcp, endpoint, length);
    result.route = decision.route;
    result.address = decision.address;
    if (decision.route != handler_route::legacy_ipv4) return result;
    result.legacy_peer.sin_family = AF_INET;
    result.legacy_peer.sin_addr.s_addr = decision.legacy_ipv4_network;
    if (endpoint->sa_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(endpoint);
        result.legacy_peer.sin_port = v4->sin_port;
    } else if (endpoint->sa_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(endpoint);
        result.legacy_peer.sin_port = v6->sin6_port;
    }
    return result;
}
}
