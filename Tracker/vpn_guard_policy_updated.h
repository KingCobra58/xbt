#pragma once
// XBT IPv4 policy: last-known-good snapshot, 30-second reload.
// Intended for XBT single-threaded event loop; NOT thread-safe.
#include "vpn_guard_ipv4.h"
#include <ctime>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <unistd.h>
#include <map>
#include <arpa/inet.h>
namespace fm_vpn {
inline bool load_policy(const std::string& path, std::vector<network>& deny, std::vector<network>& allow, std::string* loaded_hash = NULL) {
    std::ifstream in(path.c_str());
    if (!in) return false;
    std::vector<network> next_deny, next_allow;
    std::string line;
    unsigned long long fnv = 14695981039346656037ULL;
    const auto hash_line = [&fnv](const std::string& value) {
        for (size_t i = 0; i < value.size(); ++i) { fnv ^= static_cast<unsigned char>(value[i]); fnv *= 1099511628211ULL; }
        fnv ^= static_cast<unsigned char>('\n'); fnv *= 1099511628211ULL;
    };
    int section = 0;
    bool saw_deny = false, saw_allow = false;
    if (!std::getline(in, line) || line != "FM_VPN_POLICY_V1") return false;
    hash_line(line);
    while (std::getline(in, line)) {
        hash_line(line);
        if (line == "[deny]") { if (saw_deny || saw_allow) return false; section=1; saw_deny=true; continue; }
        if (line == "[allow]") { if (!saw_deny || saw_allow) return false; section=2; saw_allow=true; continue; }
        if (line.empty()) continue;
        if (section == 0 || line[0] == '#' || line.find_first_of(" \t\r") != std::string::npos) return false;
        network n;
        if (!parse_cidr(line, n)) return false;
        if (section == 1) next_deny.push_back(n); else next_allow.push_back(n);
        if (next_deny.size() + next_allow.size() > 2000000) return false;
    }
    if (!in.eof() || !saw_deny || !saw_allow) return false;
    if (loaded_hash) { std::ostringstream out; out << std::hex << std::setfill('0') << std::setw(16) << fnv; *loaded_hash = out.str(); }
    deny.swap(next_deny); allow.swap(next_allow);
    return true;
}
// The service manager must set an absolute policy path when XBT runs as a daemon.
// Without this, the historical relative path is resolved against the process CWD.
inline std::string policy_path() {
    const char* configured = std::getenv("FM_VPN_POLICY_PATH");
    return configured && configured[0] ? std::string(configured) : std::string("vpn_guard_policy_ipv4.txt");
}
// Explicit opt-in. Audit logs matching IPs without blocking; enforcement fails closed on absent policy.
// Optional AdminCP mode bridge. When configured, this file is authoritative.
// Mode file accepts exactly one line; do not expose its path to untrusted writers.
// A missing/malformed configured file fails closed; the bridge must be
// provisioned before setting FM_VPN_MODE_FILE on a production daemon.
enum mode_state { mode_disabled, mode_audit, mode_enforce, mode_invalid };
inline mode_state current_mode() {
    const char* file = std::getenv("FM_VPN_MODE_FILE");
    if (file && file[0]) {
        std::ifstream in(file);
        std::string line, extra;
        if (!in || !std::getline(in, line) || std::getline(in, extra)) return mode_invalid;
        if (line == "FM_VPN_MODE=disabled") return mode_disabled;
        if (line == "FM_VPN_MODE=audit") return mode_audit;
        if (line == "FM_VPN_MODE=enforce") return mode_enforce;
        return mode_invalid;
    }
    const char* mode = std::getenv("FM_VPN_MODE");
    if (mode && std::string(mode) == "enforce") return mode_enforce;
    if (mode && std::string(mode) == "audit") return mode_audit;
    return mode_disabled;
}
inline bool enforcement_enabled() { const mode_state m = current_mode(); return m == mode_enforce || m == mode_invalid; }
// Emit at most one event per source IP/protocol/mode per minute to limit log floods.
// The cache is bounded and only used by the single-threaded XBT event loop.
inline void log_decision(uint32_t ip, const char* protocol, const char* decision) {
    static std::map<std::string, std::time_t> last_logged;
    const std::time_t now = std::time(NULL);
    struct in_addr address;
    address.s_addr = ip;
    char text[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &address, text, sizeof(text))) return;
    const std::string key = std::string(protocol) + ":" + decision + ":" + text;
    auto it = last_logged.find(key);
    if (it != last_logged.end() && now >= it->second && now - it->second < 60) return;
    if (last_logged.size() >= 4096) last_logged.clear();
    last_logged[key] = now;
    std::cerr << "VPN Guard: " << decision << " protocol=" << protocol
              << " source=" << text << std::endl;
}
// Optional daemon-authored reload receipt. Must reside in a private directory.
// An atomic rename ensures readers never see a partial receipt.
inline void publish_loaded_receipt(const std::string& digest) {
    const char* configured = std::getenv("FM_VPN_LOADED_STATUS_PATH");
    if (!configured || !configured[0]) return;
    const std::string path(configured);
    const std::string temp = path + "." + std::to_string(static_cast<long long>(getpid())) + ".tmp";
    std::ofstream out(temp.c_str(), std::ios::out | std::ios::trunc);
    if (!out) return;
    out << "FM_VPN_LOADED_FNV64=" << digest << "\n"
        << "FM_VPN_LOADED_AT=" << static_cast<long long>(std::time(NULL)) << "\n"
        << "FM_VPN_LOADED_PID=" << static_cast<long long>(getpid()) << "\n";
    out.close();
    if (!out.good() || std::rename(temp.c_str(), path.c_str()) != 0) std::remove(temp.c_str());
}
inline bool denied_ipv4(uint32_t ip, const char* protocol = "unknown") {
    const mode_state mode = current_mode();
    if (mode == mode_disabled) return false;
    if (mode == mode_invalid) { log_decision(ip, protocol, "blocked-invalid-mode"); return true; }
    static std::vector<network> deny, allow;
    static bool initialized = false;
    static std::time_t last_attempt = 0;
    const std::time_t now = std::time(NULL);
    if (!initialized || now < last_attempt || now - last_attempt >= 30) {
        last_attempt = now;
        std::vector<network> next_deny, next_allow;
        std::string loaded_hash;
        if (load_policy(policy_path(), next_deny, next_allow, &loaded_hash)) {
            deny.swap(next_deny); allow.swap(next_allow); initialized = true;
            publish_loaded_receipt(loaded_hash);
        } else {
            // Enforcement fails closed if no valid policy was ever loaded.
            // An invalid reload retains the last known-good policy.
            static bool warned = false;
            if (!warned) {
                std::cerr << "VPN Guard: policy unavailable or invalid at " << policy_path()
                          << "; retaining previous policy (or denying all if none loaded)" << std::endl;
                warned = true;
            }
        }
    }
    if (!initialized) {
        if (mode == mode_enforce) { log_decision(ip, protocol, "blocked-missing-policy"); return true; }
        return false; // Audit mode never blocks, even if the policy is missing.
    }
    const bool matched = matches(deny, ip) && !matches(allow, ip);
    if (matched) log_decision(ip, protocol, mode == mode_audit ? "audit-match" : "blocked-match");
    return matched && mode == mode_enforce;
}
}
