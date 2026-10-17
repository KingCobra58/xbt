#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace vpn_guard {
struct Network {
    int family = 0;
    std::array<unsigned char, 16> address{};
    unsigned prefix = 0;
};
bool parse_cidr(const std::string& cidr, Network& out);
bool matches(const Network& network, const std::string& ip);
bool matches_any(const std::vector<Network>& networks, const std::string& ip);
}
