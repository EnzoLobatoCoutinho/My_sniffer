/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** rate_spike_analyzer.cpp
*/

#include "analysis/rate_spike_analyzer.hpp"
#include "parser/bytes_utils.hpp"

#include <sstream>

namespace sniffer {

    RateSpikeAnalyzer::RateSpikeAnalyzer(std::chrono::milliseconds window, std::size_t maxPacketsPerWindow)
        : window_(window), maxPacketsPerWindow_(maxPacketsPerWindow) {}

    std::vector<Alert> RateSpikeAnalyzer::onPacket(const Packet& packet) {
        if (!packet.ipv4().has_value()) {
            return {};
        }

        const uint32_t srcIp = packet.ipv4()->src_ip;
        SourceState& state = sources_[srcIp];
        const auto now = packet.timestamp();

        state.timestamps.push_back(now);
        while (!state.timestamps.empty() && now - state.timestamps.front() > window_) {
            state.timestamps.pop_front();
        }

        if (state.timestamps.size() <= maxPacketsPerWindow_) {
            state.alerting = false;
            return {};
        }

        if (state.alerting) {
            return {};
        }

        state.alerting = true;
        std::ostringstream oss;
        oss << "traffic spike from " << bytes::ipv4ToString(srcIp) << ": "
            << state.timestamps.size() << " packets in " << window_.count() << "ms";
        return {Alert{"RateSpikeAnalyzer", oss.str()}};
    }

} // namespace sniffer
