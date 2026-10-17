#pragma once
#include "vpn_announce_handler_gate.h"
#include <netinet/in.h>
namespace vpn_guard {
// Boundary for the original Cconnection(Csocket, sockaddr_in) constructor.
// No native IPv6 endpoint can be converted to sockaddr_in.
struct tcp_accept_result {
    handler_route route = handler_route::reject_invalid;
    sockaddr_in legacy_peer{};
    announce_address address{};
};
tcp_accept_result prepare_tcp_accept(const sockaddr* endpoint, socklen_t length);
}
