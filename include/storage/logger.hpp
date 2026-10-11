/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** logger.hpp
*/

#ifndef MY_SNIFFER_STORAGE_LOGGER_HPP_
    #define MY_SNIFFER_STORAGE_LOGGER_HPP_

#include "analysis/ianalyzer.hpp"
#include "core/packet.hpp"

#include <fstream>
#include <string>

namespace sniffer {

class Logger {
    public:
        explicit Logger(const std::string& path);

        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;

        void logPacket(const Packet& packet);
        void logAlert(const Alert& alert);

    private:
        std::ofstream file_;
};

} // namespace sniffer

#endif // MY_SNIFFER_STORAGE_LOGGER_HPP_
