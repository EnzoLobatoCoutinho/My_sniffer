/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** packet.cpp
*/

#include "core/packet.hpp"

namespace sniffer {

    Packet::Packet(std::chrono::system_clock::time_point timestamp,
                   std::size_t length,
                   std::optional<EthernetHeader> ethernet,
                   std::optional<Ipv4Header> ipv4,
                   std::optional<TransportHeader> transport,
                   std::vector<uint8_t> payload)
        : timestamp_(timestamp),
          length_(length),
          ethernet_(std::move(ethernet)),
          ipv4_(std::move(ipv4)),
          transport_(std::move(transport)),
          payload_(std::move(payload)) {}

    const std::chrono::system_clock::time_point& Packet::timestamp() const {
        return timestamp_;
    }

    std::size_t Packet::length() const {
        return length_;
    }

    const std::optional<EthernetHeader>& Packet::ethernet() const {
        return ethernet_;
    }

    const std::optional<Ipv4Header>& Packet::ipv4() const {
        return ipv4_;
    }

    const std::optional<TransportHeader>& Packet::transport() const {
        return transport_;
    }

    const std::vector<uint8_t>& Packet::payload() const {
        return payload_;
    }

} // namespace sniffer
