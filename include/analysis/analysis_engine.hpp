/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** analysis_engine.hpp
*/

#ifndef MY_SNIFFER_ANALYSIS_ANALYSIS_ENGINE_HPP_
    #define MY_SNIFFER_ANALYSIS_ANALYSIS_ENGINE_HPP_

#include "analysis/ianalyzer.hpp"

#include <memory>
#include <vector>

namespace sniffer {

class AnalysisEngine {
    public:
        void addAnalyzer(std::unique_ptr<IAnalyzer> analyzer);

        std::vector<Alert> onPacket(const Packet& packet);

    private:
        std::vector<std::unique_ptr<IAnalyzer>> analyzers_;
};

} // namespace sniffer

#endif // MY_SNIFFER_ANALYSIS_ANALYSIS_ENGINE_HPP_
