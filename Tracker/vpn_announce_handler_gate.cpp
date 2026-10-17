#include "vpn_announce_handler_gate.h"
namespace vpn_guard {
handler_decision route_announce_endpoint(announce_transport transport,
                                         const sockaddr* endpoint, socklen_t length) {
    handler_decision d{};
    const auto ingress = prepare_announce_ingress(transport, endpoint, length);
    d.address = ingress.address;
    switch (ingress.status) {
    case ingress_status::legacy_ipv4_ready:
        d.route = handler_route::legacy_ipv4;
        d.legacy_ipv4_network = ingress.legacy_ipv4_network;
        break;
    case ingress_status::native_ipv6_sidecar:
        d.route = handler_route::defer_native_ipv6;
        break;
    case ingress_status::invalid_endpoint:
        break;
    }
    return d;
}
}
