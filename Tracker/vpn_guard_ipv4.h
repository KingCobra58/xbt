#pragma once
// xbtitFM VPN Guard: dependency-free IPv4 CIDR matching helper.
// Development component; NOT connected to XBT announce handling.
#include <stdint.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <arpa/inet.h>

namespace fm_vpn {
struct network { uint32_t prefix; uint32_t mask; };
inline bool parse_cidr(const std::string& value, network& out) {
    const std::string::size_type slash = value.find('/');
    const std::string addr = value.substr(0, slash);
    struct in_addr parsed;
    if (inet_pton(AF_INET, addr.c_str(), &parsed) != 1) return false;
    unsigned int bits = 32;
    if (slash != std::string::npos) {
        const std::string suffix = value.substr(slash + 1);
        if (suffix.empty()) return false;
        for (std::string::size_type i = 0; i < suffix.size(); ++i)
            if (suffix[i] < '0' || suffix[i] > '9') return false;
        const unsigned long b = std::strtoul(suffix.c_str(), NULL, 10);
        if (b > 32) return false;
        bits = static_cast<unsigned int>(b);
    }
    out.mask = bits == 0 ? 0 : (0xffffffffu << (32 - bits));
    out.prefix = ntohl(parsed.s_addr) & out.mask;
    return true;
}
inline bool contains(const network& n, uint32_t network_order_ipv4) {
    return (ntohl(network_order_ipv4) & n.mask) == n.prefix;
}
inline bool load_list(const std::string& path, std::vector<network>& out) {
    std::ifstream in(path.c_str());
    if (!in) return false;
    std::vector<network> parsed;
    std::string line;
    while (std::getline(in, line)) {
        const std::string::size_type comment = line.find('#');
        if (comment != std::string::npos) line.erase(comment);
        const std::string::size_type first = line.find_first_not_of(" \t\r");
        if (first == std::string::npos) continue;
        const std::string::size_type last = line.find_last_not_of(" \t\r");
        network n;
        if (!parse_cidr(line.substr(first, last-first+1), n)) return false;
        parsed.push_back(n);
        if (parsed.size() > 2000000) return false;
    }
    out.swap(parsed); // preserve last known-good list on parse errors
    return true;
}
inline bool matches(const std::vector<network>& list, uint32_t ip) {
    for (std::vector<network>::const_iterator it = list.begin(); it != list.end(); ++it)
        if (contains(*it, ip)) return true;
    return false;
}
}
