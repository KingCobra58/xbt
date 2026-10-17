#include "vpn_socket_address.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
namespace vpn_guard {
bool peer_ip(const sockaddr* address, socklen_t length, std::string& result) {
    result.clear();
    if (!address) return false;
    char buffer[INET6_ADDRSTRLEN] = {};
    if (address->sa_family == AF_INET) {
        if (length < sizeof(sockaddr_in)) return false;
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        if (!inet_ntop(AF_INET, &ipv4->sin_addr, buffer, sizeof(buffer))) return false;
    } else if (address->sa_family == AF_INET6) {
        if (length < sizeof(sockaddr_in6)) return false;
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        if (IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr)) {
            in_addr v4{};
            std::memcpy(&v4, &ipv6->sin6_addr.s6_addr[12], sizeof(v4));
            if (!inet_ntop(AF_INET, &v4, buffer, sizeof(buffer))) return false;
        } else {
            if (!inet_ntop(AF_INET6, &ipv6->sin6_addr, buffer, sizeof(buffer))) return false;
        }
    } else return false;
    result.assign(buffer);
    return true;
}
}
