/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** packet_builder.cpp
*/

#include "core/packet_builder.hpp"

#include <utility>

namespace sniffer {

    PacketBuilder& PacketBuilder::setTimestamp(std::chrono::system_clock::time_point timestamp) {
        timestamp_ = timestamp;
        return *this;
    }

    PacketBuilder& PacketBuilder::setLength(std::size_t length) {
        length_ = length;
        return *this;
    }

    PacketBuilder& PacketBuilder::setEthernet(EthernetHeader ethernet) {
        ethernet_ = std::move(ethernet);
        return *this;
    }

    PacketBuilder& PacketBuilder::setIpv4(Ipv4Header ipv4) {
        ipv4_ = std::move(ipv4);
        return *this;
    }

    PacketBuilder& PacketBuilder::setTransport(TransportHeader transport) {
        transport_ = std::move(transport);
        return *this;
    }

    PacketBuilder& PacketBuilder::setPayload(std::vector<uint8_t> payload) {
        payload_ = std::move(payload);
        return *this;
    }

    Packet PacketBuilder::build() const {
        return Packet(timestamp_, length_, ethernet_, ipv4_, transport_, payload_);
    }

    const std::optional<EthernetHeader>& PacketBuilder::ethernet() const {
        return ethernet_;
    }

    const std::optional<Ipv4Header>& PacketBuilder::ipv4() const {
        return ipv4_;
    }

    const std::optional<TransportHeader>& PacketBuilder::transport() const {
        return transport_;
    }

    const std::vector<uint8_t>& PacketBuilder::payload() const {
        return payload_;
    }

} // namespace sniffer
