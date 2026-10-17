#include "vpn_announce_ingress.h"
namespace vpn_guard {
announce_ingress_result prepare_announce_ingress(announce_transport transport,
                                                 const sockaddr* remote, socklen_t remote_length) {
    announce_ingress_result result{};
    result.transport = transport;
    if (!make_announce_address(remote, remote_length, result.address)) return result;
    if (legacy_ipv4_value(result.address, result.legacy_ipv4_network)) {
        result.status = ingress_status::legacy_ipv4_ready;
    } else {
        result.status = ingress_status::native_ipv6_sidecar;
    }
    return result;
}
}
