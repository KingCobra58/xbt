#pragma once
#include "vpn_announce_address.h"
#include <cstdint>
namespace vpn_guard {
enum class announce_transport { tcp, udp };
enum class ingress_status { invalid_endpoint, legacy_ipv4_ready, native_ipv6_sidecar };
struct announce_ingress_result {
    announce_transport transport = announce_transport::tcp;
    ingress_status status = ingress_status::invalid_endpoint;
    announce_address address{};
    std::uint32_t legacy_ipv4_network = 0;
};
// Transport-neutral preparation only. Not connected to production XBT handlers.
// No IPv6 address may be coerced into a legacy IPv4 field.
announce_ingress_result prepare_announce_ingress(announce_transport transport,
                                                 const sockaddr* remote, socklen_t remote_length);
}
