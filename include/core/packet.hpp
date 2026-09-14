/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** packet.hpp
*/

#ifndef MY_SNIFFER_CORE_PACKET_HPP_
    #define MY_SNIFFER_CORE_PACKET_HPP_

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>
#include <utility>

namespace sniffer {

struct EthernetHeader {
    std::array<uint8_t, 6> src_mac{};
    std::array<uint8_t, 6> dst_mac{};
    uint16_t ethertype{0};
};

struct Ipv4Header {
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint8_t protocol{0};
    uint8_t ttl{0};
};

struct TransportHeader {
    uint16_t src_port{0};
    uint16_t dst_port{0};
};

class Packet {
    public:
        Packet(std::chrono::system_clock::time_point timestamp,
               std::size_t length,
               std::optional<EthernetHeader> ethernet,
               std::optional<Ipv4Header> ipv4,
               std::optional<TransportHeader> transport,
               std::vector<uint8_t> payload);

        const std::chrono::system_clock::time_point& timestamp() const;
        std::size_t length() const;

        const std::optional<EthernetHeader>& ethernet() const;
        const std::optional<Ipv4Header>& ipv4() const;
        const std::optional<TransportHeader>& transport() const;
        const std::vector<uint8_t>& payload() const;

    private:
        std::chrono::system_clock::time_point timestamp_;
        std::size_t length_;
        std::optional<EthernetHeader> ethernet_;
        std::optional<Ipv4Header> ipv4_;
        std::optional<TransportHeader> transport_;
        std::vector<uint8_t> payload_;
    };

} // namespace sniffer

#endif // MY_SNIFFER_CORE_PACKET_HPP_