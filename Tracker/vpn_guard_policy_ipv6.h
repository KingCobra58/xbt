#pragma once
// IPv6 policy snapshot parser. Not connected to XBT sockets yet.
#include "vpn_guard_ipv6.h"
#include <fstream>
namespace fm_vpn {
inline bool load_policy6(const std::string& path, std::vector<network6>& deny, std::vector<network6>& allow) {
    std::ifstream in(path.c_str());
    if (!in) return false;
    std::string line;
    if (!std::getline(in,line) || line != "FM_VPN_POLICY_V1") return false;
    int section=0;
    std::vector<network6> new_deny, new_allow;
    while (std::getline(in,line)) {
        if (line == "[deny]" && section==0) {section=1;continue;}
        if (line == "[allow]" && section==1) {section=2;continue;}
        if (line.empty()) continue;
        if (section==0 || line.find_first_of(" \t\r") != std::string::npos) return false;
        network6 entry;
        if (!parse_cidr6(line,entry)) return false;
        if (section==1) new_deny.push_back(entry); else new_allow.push_back(entry);
        if (new_deny.size()+new_allow.size()>2000000) return false;
    }
    if (!in.eof() || section!=2) return false;
    deny.swap(new_deny);allow.swap(new_allow);
    return true;
}
inline bool denied_ipv6(const std::vector<network6>& deny,const std::vector<network6>& allow,const in6_addr& ip) {
    return matches6(deny,ip) && !matches6(allow,ip);
}
}
