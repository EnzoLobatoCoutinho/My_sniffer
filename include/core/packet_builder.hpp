/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** packet_builder.hpp
*/

#ifndef MY_SNIFFER_CORE_PACKET_BUILDER_HPP_
    #define MY_SNIFFER_CORE_PACKET_BUILDER_HPP_

#include "core/packet.hpp"

namespace sniffer {

class PacketBuilder {
    public:
        PacketBuilder& setTimestamp(std::chrono::system_clock::time_point timestamp);
        PacketBuilder& setLength(std::size_t length);
        PacketBuilder& setEthernet(EthernetHeader ethernet);
        PacketBuilder& setIpv4(Ipv4Header ipv4);
        PacketBuilder& setTransport(TransportHeader transport);
        PacketBuilder& setPayload(std::vector<uint8_t> payload);

        Packet build() const;

    private:
        std::chrono::system_clock::time_point timestamp_{};
        std::size_t length_{0};
        std::optional<EthernetHeader> ethernet_;
        std::optional<Ipv4Header> ipv4_;
        std::optional<TransportHeader> transport_;
        std::vector<uint8_t> payload_;
};

} // namespace sniffer

#endif // MY_SNIFFER_CORE_PACKET_BUILDER_HPP_
