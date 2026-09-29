/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** port_protocol_analyzer.cpp
*/

#include "analysis/port_protocol_analyzer.hpp"

#include <algorithm>
#include <array>
#include <sstream>
#include <string>
#include <utility>

namespace sniffer {

    namespace {
        bool looksLikeHttp(const std::vector<uint8_t>& payload) {
            static const std::array<std::string, 9> kPrefixes = {
                "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "HTTP/",
            };

            const std::size_t len = std::min(payload.size(), static_cast<std::size_t>(16));
            const std::string text(reinterpret_cast<const char*>(payload.data()), len);

            for (const auto& prefix : kPrefixes) {
                if (text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0) {
                    return true;
                }
            }
            return false;
        }

        bool looksLikeTls(const std::vector<uint8_t>& payload) {
            if (payload.empty()) {
                return true;
            }
            const uint8_t contentType = payload[0];
            return contentType >= 20 && contentType <= 23;
        }
    } // namespace

    PortProtocolAnalyzer::PortProtocolAnalyzer() {
        expectations_[80] = looksLikeHttp;
        expectations_[443] = looksLikeTls;
    }

    void PortProtocolAnalyzer::addExpectation(uint16_t port, Validator validator) {
        expectations_[port] = std::move(validator);
    }

    std::vector<Alert> PortProtocolAnalyzer::onPacket(const Packet& packet) {
        if (!packet.transport().has_value() || packet.payload().empty()) {
            return {};
        }

        const auto checkPort = [this, &packet](uint16_t port) -> std::vector<Alert> {
            const auto it = expectations_.find(port);
            if (it == expectations_.end() || it->second(packet.payload())) {
                return {};
            }
            std::ostringstream oss;
            oss << "unexpected protocol on standard port " << port;
            return {Alert{"PortProtocolAnalyzer", oss.str()}};
        };

        auto alerts = checkPort(packet.transport()->dst_port);
        if (!alerts.empty()) {
            return alerts;
        }
        return checkPort(packet.transport()->src_port);
    }

} // namespace sniffer
