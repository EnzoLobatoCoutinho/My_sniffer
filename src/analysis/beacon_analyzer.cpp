/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** beacon_analyzer.cpp
*/

#include "analysis/beacon_analyzer.hpp"
#include "parser/bytes_utils.hpp"

#include <algorithm>
#include <cmath>
#include <sstream>

namespace sniffer {

    BeaconAnalyzer::BeaconAnalyzer(std::size_t minSamples, double toleranceRatio)
        : minSamples_(minSamples), toleranceRatio_(toleranceRatio) {}

    std::vector<Alert> BeaconAnalyzer::onPacket(const Packet& packet) {
        if (!packet.ipv4().has_value() || !packet.transport().has_value()) {
            return {};
        }

        const FlowKey key{packet.ipv4()->src_ip, packet.ipv4()->dst_ip, packet.transport()->dst_port};
        FlowState& state = flows_[key];
        const auto now = packet.timestamp();

        if (!state.hasLast) {
            state.lastTimestamp = now;
            state.hasLast = true;
            return {};
        }

        const auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(now - state.lastTimestamp);
        state.lastTimestamp = now;

        state.intervals.push_back(interval);
        if (state.intervals.size() > minSamples_) {
            state.intervals.pop_front();
        }
        if (state.intervals.size() < minSamples_) {
            return {};
        }

        long long sum = 0;
        for (const auto& iv : state.intervals) {
            sum += iv.count();
        }
        const double mean = static_cast<double>(sum) / static_cast<double>(state.intervals.size());

        if (mean <= 0.0) {
            state.alerting = false;
            return {};
        }

        double maxDeviation = 0.0;
        for (const auto& iv : state.intervals) {
            const double deviation = std::fabs(static_cast<double>(iv.count()) - mean) / mean;
            maxDeviation = std::max(maxDeviation, deviation);
        }

        if (maxDeviation > toleranceRatio_) {
            state.alerting = false;
            return {};
        }

        if (state.alerting) {
            return {};
        }

        state.alerting = true;
        std::ostringstream oss;
        oss << "regular beaconing from " << bytes::ipv4ToString(std::get<0>(key))
            << " to " << bytes::ipv4ToString(std::get<1>(key)) << ":" << std::get<2>(key)
            << " every ~" << static_cast<long long>(mean) << "ms";
        return {Alert{"BeaconAnalyzer", oss.str()}};
    }

} // namespace sniffer
