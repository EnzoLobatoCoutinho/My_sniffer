/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** port_protocol_analyzer.hpp
*/

#ifndef MY_SNIFFER_ANALYSIS_PORT_PROTOCOL_ANALYZER_HPP_
    #define MY_SNIFFER_ANALYSIS_PORT_PROTOCOL_ANALYZER_HPP_

#include "analysis/ianalyzer.hpp"

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

namespace sniffer {

class PortProtocolAnalyzer : public IAnalyzer {
    public:
        using Validator = std::function<bool(const std::vector<uint8_t>& payload)>;

        PortProtocolAnalyzer();

        void addExpectation(uint16_t port, Validator validator);

        std::vector<Alert> onPacket(const Packet& packet) override;

    private:
        std::unordered_map<uint16_t, Validator> expectations_;
};

} // namespace sniffer

#endif // MY_SNIFFER_ANALYSIS_PORT_PROTOCOL_ANALYZER_HPP_
