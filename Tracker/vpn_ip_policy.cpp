#include "vpn_ip_policy.h"
#include <arpa/inet.h>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace vpn_guard {
static bool parse_ip(const std::string& input, int& family, std::array<unsigned char, 16>& bytes) {
    if (input.empty() || input.find('%') != std::string::npos || input.find_first_of(" \t\r\n") != std::string::npos) return false;
    bytes.fill(0);
    if (inet_pton(AF_INET, input.c_str(), bytes.data()) == 1) { family = AF_INET; return true; }
    if (inet_pton(AF_INET6, input.c_str(), bytes.data()) == 1) { family = AF_INET6; return true; }
    return false;
}
bool parse_cidr(const std::string& cidr, Network& out) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos || cidr.find('/', slash + 1) != std::string::npos) return false;
    Network candidate;
    if (!parse_ip(cidr.substr(0, slash), candidate.family, candidate.address)) return false;
    std::string suffix = cidr.substr(slash + 1);
    if (suffix.empty() || !std::all_of(suffix.begin(), suffix.end(), [](unsigned char c){return c >= '0' && c <= '9';})) return false;
    errno = 0;
    char* end = nullptr;
    unsigned long p = std::strtoul(suffix.c_str(), &end, 10);
    if (errno || !end || *end || p > (candidate.family == AF_INET ? 32UL : 128UL)) return false;
    candidate.prefix = static_cast<unsigned>(p);
    out = candidate;
    return true;
}
bool matches(const Network& network, const std::string& ip) {
    int family = 0;
    std::array<unsigned char, 16> address{};
    if (!parse_ip(ip, family, address) || family != network.family) return false;
    const unsigned full = network.prefix / 8, rem = network.prefix % 8;
    if (full && std::memcmp(address.data(), network.address.data(), full) != 0) return false;
    if (rem) {
        const unsigned char mask = static_cast<unsigned char>(0xffu << (8 - rem));
        if ((address[full] & mask) != (network.address[full] & mask)) return false;
    }
    return true;
}
bool matches_any(const std::vector<Network>& networks, const std::string& ip) {
    for (const auto& network : networks) if (matches(network, ip)) return true;
    return false;
}
}
