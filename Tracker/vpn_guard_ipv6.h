#pragma once
// IPv6 CIDR matcher, standalone development component. Not yet wired into XBT sockets.
#include <array>
#include <string>
#include <vector>
#include <cstdlib>
#include <arpa/inet.h>
namespace fm_vpn {
struct network6 { std::array<unsigned char,16> prefix; unsigned int bits; };
inline bool parse_cidr6(const std::string& value, network6& out) {
    const std::string::size_type slash = value.find('/');
    if (slash != std::string::npos && value.find('/', slash+1) != std::string::npos) return false;
    const std::string addr = value.substr(0, slash);
    struct in6_addr parsed;
    if (inet_pton(AF_INET6, addr.c_str(), &parsed) != 1) return false;
    unsigned int bits = 128;
    if (slash != std::string::npos) {
        const std::string suffix = value.substr(slash+1);
        if (suffix.empty() || suffix.size() > 3) return false;
        for (size_t i=0;i<suffix.size();++i) if (suffix[i]<'0'||suffix[i]>'9') return false;
        const unsigned long n = std::strtoul(suffix.c_str(), NULL, 10);
        if (n > 128) return false;
        bits = static_cast<unsigned int>(n);
    }
    out.bits = bits;
    for (size_t i=0;i<16;++i) {
        const unsigned int remain = bits > i*8 ? bits-static_cast<unsigned int>(i*8) : 0;
        const unsigned char mask = remain >= 8 ? 255 : (remain == 0 ? 0 : static_cast<unsigned char>(255 << (8-remain)));
        out.prefix[i] = parsed.s6_addr[i] & mask;
    }
    return true;
}
inline bool contains6(const network6& net, const in6_addr& ip) {
    for (size_t i=0;i<16;++i) {
        const unsigned int remain = net.bits > i*8 ? net.bits-static_cast<unsigned int>(i*8) : 0;
        const unsigned char mask = remain >= 8 ? 255 : (remain == 0 ? 0 : static_cast<unsigned char>(255 << (8-remain)));
        if ((ip.s6_addr[i] & mask) != net.prefix[i]) return false;
    }
    return true;
}
inline bool matches6(const std::vector<network6>& nets, const in6_addr& ip) {
    for (size_t i=0;i<nets.size();++i) if (contains6(nets[i],ip)) return true;
    return false;
}
}
