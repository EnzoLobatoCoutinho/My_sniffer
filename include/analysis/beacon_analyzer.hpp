/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** beacon_analyzer.hpp
*/

#ifndef MY_SNIFFER_ANALYSIS_BEACON_ANALYZER_HPP_
    #define MY_SNIFFER_ANALYSIS_BEACON_ANALYZER_HPP_

#include "analysis/ianalyzer.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <tuple>

namespace sniffer {

// source IP, destination IP, destination port
class BeaconAnalyzer : public IAnalyzer {
    public:
        BeaconAnalyzer(std::size_t minSamples, double toleranceRatio);

        std::vector<Alert> onPacket(const Packet& packet) override;

    private:
        using FlowKey = std::tuple<uint32_t, uint32_t, uint16_t>;

        struct FlowState {
            std::chrono::system_clock::time_point lastTimestamp{};
            bool hasLast = false;
            std::deque<std::chrono::milliseconds> intervals;
            bool alerting = false;
        };

        std::size_t minSamples_;
        double toleranceRatio_;
        std::map<FlowKey, FlowState> flows_;
};

} // namespace sniffer

#endif // MY_SNIFFER_ANALYSIS_BEACON_ANALYZER_HPP_
