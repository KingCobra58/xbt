#pragma once
#include "vpn_peer_identity.h"
#include <map>
#include <string>
#include <cstdint>
namespace vpn_guard {
// Standalone dual-stack peer index. Not wired into XBT's legacy t_peers.
struct peer_key {
    std::string ip; // normalized by make_peer_identity
    std::uint32_t user_id = 0;
    bool operator<(const peer_key& o) const {
        return ip < o.ip || (ip == o.ip && user_id < o.user_id);
    }
};
struct peer_record {
    peer_identity endpoint;
    std::string peer_id;
    std::uint64_t last_seen = 0;
};
class peer_store {
    std::map<peer_key, peer_record> peers_;
public:
    bool upsert(const peer_identity& endpoint, std::uint32_t user_id,
                const std::string& peer_id, std::uint64_t seen);
    bool erase(const peer_identity& endpoint, std::uint32_t user_id);
    const peer_record* find(const peer_identity& endpoint, std::uint32_t user_id) const;
    std::size_t size() const { return peers_.size(); }
    std::size_t expire_before(std::uint64_t cutoff);
    // Produce separate BEP 23/BEP 7 compact peer blobs, excluding requesting peer.
    void compact_peers(std::string& peers4, std::string& peers6,
                       const peer_identity* exclude = nullptr,
                       std::uint32_t exclude_user_id = 0) const;
};
}
