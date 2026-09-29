/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** foreign_ip_analyzer.cpp
*/

#include "analysis/foreign_ip_analyzer.hpp"
#include "parser/bytes_utils.hpp"

#include <sstream>
#include <utility>

namespace sniffer {

    namespace {
        bool isPrivateOrLoopback(uint32_t ip) {
            const auto a = static_cast<uint8_t>((ip >> 24) & 0xFF);
            const auto b = static_cast<uint8_t>((ip >> 16) & 0xFF);

            if (a == 10) {
                return true;
            }
            if (a == 127) {
                return true;
            }
            if (a == 172 && b >= 16 && b <= 31) {
                return true;
            }
            if (a == 192 && b == 168) {
                return true;
            }
            return false;
        }
    } // namespace

    ForeignIpAnalyzer::ForeignIpAnalyzer(std::unordered_set<uint32_t> allowedForeignIps)
        : allowedForeignIps_(std::move(allowedForeignIps)) {}

    std::vector<Alert> ForeignIpAnalyzer::onPacket(const Packet& packet) {
        if (!packet.ipv4().has_value()) {
            return {};
        }

        const uint32_t dst = packet.ipv4()->dst_ip;

        if (isPrivateOrLoopback(dst) || allowedForeignIps_.count(dst) > 0) {
            return {};
        }

        if (!alreadyFlagged_.insert(dst).second) {
            return {};
        }

        std::ostringstream oss;
        oss << "unauthorized connection to foreign IP " << bytes::ipv4ToString(dst);
        return {Alert{"ForeignIpAnalyzer", oss.str()}};
    }

} // namespace sniffer
