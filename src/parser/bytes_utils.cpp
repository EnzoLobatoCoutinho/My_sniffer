/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** bytes_utils.cpp
*/

#include "parser/bytes_utils.hpp"

#include <iomanip>
#include <sstream>

namespace sniffer::bytes {

    uint16_t readUint16BE(const uint8_t* data) {
        return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
    }

    uint32_t readUint32BE(const uint8_t* data) {
        return (static_cast<uint32_t>(data[0]) << 24)
             | (static_cast<uint32_t>(data[1]) << 16)
             | (static_cast<uint32_t>(data[2]) << 8)
             | static_cast<uint32_t>(data[3]);
    }

    std::string macToString(const std::array<uint8_t, 6>& mac) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (std::size_t i = 0; i < mac.size(); ++i) {
            if (i != 0) {
                oss << ':';
            }
            oss << std::setw(2) << static_cast<int>(mac[i]);
        }
        return oss.str();
    }

    std::string ipv4ToString(uint32_t ip) {
        std::ostringstream oss;
        oss << ((ip >> 24) & 0xFF) << '.'
            << ((ip >> 16) & 0xFF) << '.'
            << ((ip >> 8) & 0xFF) << '.'
            << (ip & 0xFF);
        return oss.str();
    }

    std::optional<uint32_t> parseIpv4(const std::string& text) {
        uint32_t result = 0;
        std::size_t octetCount = 0;
        std::size_t digitsInOctet = 0;
        unsigned int octetValue = 0;

        for (std::size_t i = 0; i <= text.size(); ++i) {
            const bool atEnd = (i == text.size());
            const char c = atEnd ? '.' : text[i];

            if (c == '.') {
                if (digitsInOctet == 0 || octetCount >= 4) {
                    return std::nullopt;
                }
                result = (result << 8) | octetValue;
                ++octetCount;
                octetValue = 0;
                digitsInOctet = 0;
                if (atEnd) {
                    break;
                }
                continue;
            }

            if (c < '0' || c > '9' || digitsInOctet >= 3) {
                return std::nullopt;
            }

            octetValue = octetValue * 10 + static_cast<unsigned int>(c - '0');
            if (octetValue > 255) {
                return std::nullopt;
            }
            ++digitsInOctet;
        }

        if (octetCount != 4) {
            return std::nullopt;
        }

        return result;
    }

} // namespace sniffer::bytes
