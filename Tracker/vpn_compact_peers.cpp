#include "vpn_compact_peers.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <string>
namespace vpn_guard {
bool append_compact_peer(const peer_identity& peer, std::string& peers4, std::string& peers6) {
    if (!peer.length || peer.port == 0) return false;
    if (peer.address.ss_family == AF_INET) {
        if (peer.length < sizeof(sockaddr_in)) return false;
        const auto& a = reinterpret_cast<const sockaddr_in&>(peer.address);
        peers4.append(reinterpret_cast<const char*>(&a.sin_addr), 4);
        peers4.append(reinterpret_cast<const char*>(&a.sin_port), 2);
        return true;
    }
    if (peer.address.ss_family == AF_INET6) {
        if (peer.length < sizeof(sockaddr_in6)) return false;
        const auto& a = reinterpret_cast<const sockaddr_in6&>(peer.address);
        if (IN6_IS_ADDR_V4MAPPED(&a.sin6_addr)) {
            peers4.append(reinterpret_cast<const char*>(&a.sin6_addr.s6_addr[12]), 4);
            peers4.append(reinterpret_cast<const char*>(&a.sin6_port), 2);
        } else {
            peers6.append(reinterpret_cast<const char*>(&a.sin6_addr), 16);
            peers6.append(reinterpret_cast<const char*>(&a.sin6_port), 2);
        }
        return true;
    }
    return false;
}
std::string compact_announce_response(unsigned complete, unsigned incomplete, unsigned interval,
                                     const std::string& peers4, const std::string& peers6) {
    std::string result = "d8:completei" + std::to_string(complete) + "e10:incompletei" +
                         std::to_string(incomplete) + "e8:intervali" + std::to_string(interval) +
                         "e12:min intervali" + std::to_string(interval) + "e5:peers" +
                         std::to_string(peers4.size()) + ":" + peers4;
    if (!peers6.empty()) result += "6:peers6" + std::to_string(peers6.size()) + ":" + peers6;
    return result + "e";
}
}
