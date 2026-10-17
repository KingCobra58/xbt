#include "vpn_udp_receive_boundary.h"
namespace vpn_guard {
udp_receive_result prepare_udp_receive(const sockaddr* endpoint, socklen_t length) {
    udp_receive_result result{};
    const auto decision = route_announce_endpoint(announce_transport::udp, endpoint, length);
    result.route = decision.route;
    result.address = decision.address;
    if (decision.route != handler_route::legacy_ipv4) return result;
    result.legacy_peer.sin_family = AF_INET;
    result.legacy_peer.sin_addr.s_addr = decision.legacy_ipv4_network;
    if (endpoint->sa_family == AF_INET) {
        result.legacy_peer.sin_port = reinterpret_cast<const sockaddr_in*>(endpoint)->sin_port;
    } else if (endpoint->sa_family == AF_INET6) {
        result.legacy_peer.sin_port = reinterpret_cast<const sockaddr_in6*>(endpoint)->sin6_port;
    }
    return result;
}
}
