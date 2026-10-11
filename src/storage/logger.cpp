/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** logger.cpp
*/

#include "storage/logger.hpp"
#include "parser/bytes_utils.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace sniffer {

    namespace {
        std::string formatTimestamp(std::chrono::system_clock::time_point tp) {
            const std::time_t time = std::chrono::system_clock::to_time_t(tp);
            const std::tm* tmPtr = std::localtime(&time);
            if (tmPtr == nullptr) {
                return "unknown-time";
            }

            std::ostringstream oss;
            oss << std::put_time(tmPtr, "%Y-%m-%d %H:%M:%S");
            return oss.str();
        }
    } // namespace

    Logger::Logger(const std::string& path) : file_(path, std::ios::app) {
        if (!file_.is_open()) {
            throw std::runtime_error("Logger: failed to open log file '" + path + "'");
        }
    }

    void Logger::logPacket(const Packet& packet) {
        file_ << "[" << formatTimestamp(packet.timestamp()) << "] "
              << "[" << packet.length() << " bytes]";
        if (packet.ipv4().has_value()) {
            file_ << " " << bytes::ipv4ToString(packet.ipv4()->src_ip)
                  << " -> " << bytes::ipv4ToString(packet.ipv4()->dst_ip)
                  << " proto=" << static_cast<int>(packet.ipv4()->protocol);
        }
        if (packet.transport().has_value()) {
            file_ << " " << packet.transport()->src_port << " -> " << packet.transport()->dst_port;
        }
        file_ << '\n';
        file_.flush();
    }

    void Logger::logAlert(const Alert& alert) {
        file_ << "[ALERT] (" << alert.analyzer << ") " << alert.message << '\n';
        file_.flush();
    }

} // namespace sniffer
