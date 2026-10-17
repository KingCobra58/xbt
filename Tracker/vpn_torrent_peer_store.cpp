#include "vpn_torrent_peer_store.h"
namespace vpn_guard {
static bool valid_hash(const std::string& h) { return h.size() == 20; }
bool torrent_peer_store::upsert(const std::string& h, const peer_identity& p, std::uint32_t u, const std::string& id, std::uint64_t seen) {
    if (!valid_hash(h)) return false;
    return torrents_[h].upsert(p, u, id, seen);
}
bool torrent_peer_store::erase(const std::string& h, const peer_identity& p, std::uint32_t u) {
    auto it = torrents_.find(h);
    if (!valid_hash(h) || it == torrents_.end()) return false;
    bool removed = it->second.erase(p, u);
    if (it->second.size() == 0) torrents_.erase(it);
    return removed;
}
const peer_record* torrent_peer_store::find(const std::string& h, const peer_identity& p, std::uint32_t u) const {
    auto it = torrents_.find(h);
    return !valid_hash(h) || it == torrents_.end() ? nullptr : it->second.find(p, u);
}
std::size_t torrent_peer_store::size(const std::string& h) const {
    auto it = torrents_.find(h);
    return !valid_hash(h) || it == torrents_.end() ? 0 : it->second.size();
}
std::size_t torrent_peer_store::expire_before(std::uint64_t cutoff) {
    std::size_t removed = 0;
    for (auto it = torrents_.begin(); it != torrents_.end(); ) {
        removed += it->second.expire_before(cutoff);
        if (it->second.size() == 0) it = torrents_.erase(it);
        else ++it;
    }
    return removed;
}
void torrent_peer_store::compact_peers(const std::string& h, std::string& p4, std::string& p6, const peer_identity* ex, std::uint32_t u) const {
    auto it = torrents_.find(h);
    if (!valid_hash(h) || it == torrents_.end()) { p4.clear(); p6.clear(); return; }
    it->second.compact_peers(p4, p6, ex, u);
}
}
