#include "vpn_tcp_accept.h"
#include <cstring>
namespace vpn_guard {
bool legacy_tcp_peer(const sockaddr_storage& peer, socklen_t length, sockaddr_in& legacy) {
    std::memset(&legacy, 0, sizeof(legacy));
    if (peer.ss_family == AF_INET && length >= sizeof(sockaddr_in)) {
        std::memcpy(&legacy, &peer, sizeof(legacy));
        return true;
    }
    if (peer.ss_family == AF_INET6 && length >= sizeof(sockaddr_in6)) {
        const sockaddr_in6* a = reinterpret_cast<const sockaddr_in6*>(&peer);
        const unsigned char* bytes = a->sin6_addr.s6_addr;
        const unsigned char mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (std::memcmp(bytes, mapped_prefix, 12) != 0) return false;
        legacy.sin_family = AF_INET;
        legacy.sin_port = a->sin6_port;
        std::memcpy(&legacy.sin_addr, bytes + 12, 4);
        return true;
    }
    return false;
}
}
