/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** ianalyzer.hpp
*/

#ifndef MY_SNIFFER_ANALYSIS_IANALYZER_HPP_
    #define MY_SNIFFER_ANALYSIS_IANALYZER_HPP_

#include "core/packet.hpp"

#include <string>
#include <vector>

namespace sniffer {

struct Alert {
    std::string analyzer;
    std::string message;
};

class IAnalyzer {
    public:
        virtual ~IAnalyzer() = default;

        virtual std::vector<Alert> onPacket(const Packet& packet) = 0;
};

} // namespace sniffer

#endif // MY_SNIFFER_ANALYSIS_IANALYZER_HPP_
