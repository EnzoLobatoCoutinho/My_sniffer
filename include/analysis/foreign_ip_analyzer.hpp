/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** foreign_ip_analyzer.hpp
*/

#ifndef MY_SNIFFER_ANALYSIS_FOREIGN_IP_ANALYZER_HPP_
    #define MY_SNIFFER_ANALYSIS_FOREIGN_IP_ANALYZER_HPP_

#include "analysis/ianalyzer.hpp"

#include <cstdint>
#include <unordered_set>

namespace sniffer {

class ForeignIpAnalyzer : public IAnalyzer {
    public:
        explicit ForeignIpAnalyzer(std::unordered_set<uint32_t> allowedForeignIps);

        std::vector<Alert> onPacket(const Packet& packet) override;

    private:
        std::unordered_set<uint32_t> allowedForeignIps_;
        std::unordered_set<uint32_t> alreadyFlagged_;
};

} // namespace sniffer

#endif // MY_SNIFFER_ANALYSIS_FOREIGN_IP_ANALYZER_HPP_
