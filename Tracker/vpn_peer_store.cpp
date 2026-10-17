#include "vpn_peer_store.h"
#include "vpn_compact_peers.h"
namespace vpn_guard {
static bool valid(const peer_identity& p) { return !p.ip.empty() && p.length != 0 && p.port != 0; }
bool peer_store::upsert(const peer_identity& p, std::uint32_t uid, const std::string& id, std::uint64_t seen) {
    if (!valid(p)) return false;
    peers_[peer_key{p.ip, uid}] = peer_record{p, id, seen};
    return true;
}
bool peer_store::erase(const peer_identity& p, std::uint32_t uid) {
    return peers_.erase(peer_key{p.ip, uid}) != 0;
}
const peer_record* peer_store::find(const peer_identity& p, std::uint32_t uid) const {
    auto it = peers_.find(peer_key{p.ip, uid});
    return it == peers_.end() ? nullptr : &it->second;
}
std::size_t peer_store::expire_before(std::uint64_t cutoff) {
    std::size_t removed = 0;
    for (auto it = peers_.begin(); it != peers_.end(); ) {
        if (it->second.last_seen < cutoff) { it = peers_.erase(it); ++removed; }
        else ++it;
    }
    return removed;
}
void peer_store::compact_peers(std::string& p4, std::string& p6,
                              const peer_identity* exclude, std::uint32_t uid) const {
    p4.clear(); p6.clear();
    for (const auto& item : peers_) {
        if (exclude && item.first.ip == exclude->ip && item.first.user_id == uid) continue;
        append_compact_peer(item.second.endpoint, p4, p6);
    }
}
}
