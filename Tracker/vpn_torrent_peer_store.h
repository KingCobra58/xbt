#pragma once
#include "vpn_peer_store.h"
#include <map>
#include <string>
namespace vpn_guard {
// A torrent ID is exactly the 20-byte binary info_hash, including embedded NULs.
class torrent_peer_store {
    std::map<std::string, peer_store> torrents_;
public:
    bool upsert(const std::string& info_hash, const peer_identity& endpoint,
                std::uint32_t user_id, const std::string& peer_id, std::uint64_t seen);
    bool erase(const std::string& info_hash, const peer_identity& endpoint, std::uint32_t user_id);
    const peer_record* find(const std::string& info_hash, const peer_identity& endpoint, std::uint32_t user_id) const;
    std::size_t size(const std::string& info_hash) const;
    std::size_t expire_before(std::uint64_t cutoff);
    void compact_peers(const std::string& info_hash, std::string& peers4, std::string& peers6,
                       const peer_identity* exclude = nullptr, std::uint32_t exclude_user_id = 0) const;
};
}
