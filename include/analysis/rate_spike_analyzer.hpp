/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** rate_spike_analyzer.hpp
*/

#ifndef MY_SNIFFER_ANALYSIS_RATE_SPIKE_ANALYZER_HPP_
    #define MY_SNIFFER_ANALYSIS_RATE_SPIKE_ANALYZER_HPP_

#include "analysis/ianalyzer.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <unordered_map>

namespace sniffer {

class RateSpikeAnalyzer : public IAnalyzer {
    public:
        RateSpikeAnalyzer(std::chrono::milliseconds window, std::size_t maxPacketsPerWindow);

        std::vector<Alert> onPacket(const Packet& packet) override;

    private:
        struct SourceState {
            std::deque<std::chrono::system_clock::time_point> timestamps;
            bool alerting = false;
        };

        std::chrono::milliseconds window_;
        std::size_t maxPacketsPerWindow_;
        std::unordered_map<uint32_t, SourceState> sources_;
};

} // namespace sniffer

#endif // MY_SNIFFER_ANALYSIS_RATE_SPIKE_ANALYZER_HPP_
