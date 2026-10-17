#pragma once
#include "vpn_announce_handler_gate.h"
#include <netinet/in.h>
namespace vpn_guard {
struct udp_receive_result {
    handler_route route = handler_route::reject_invalid;
    sockaddr_in legacy_peer{};
    announce_address address{};
};
udp_receive_result prepare_udp_receive(const sockaddr* endpoint, socklen_t length);
}
