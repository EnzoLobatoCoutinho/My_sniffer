/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** analysis_engine.cpp
*/

#include "analysis/analysis_engine.hpp"

#include <utility>

namespace sniffer {

    void AnalysisEngine::addAnalyzer(std::unique_ptr<IAnalyzer> analyzer) {
        analyzers_.push_back(std::move(analyzer));
    }

    std::vector<Alert> AnalysisEngine::onPacket(const Packet& packet) {
        std::vector<Alert> alerts;
        for (const auto& analyzer : analyzers_) {
            auto fromThis = analyzer->onPacket(packet);
            alerts.insert(alerts.end(), fromThis.begin(), fromThis.end());
        }
        return alerts;
    }

} // namespace sniffer
