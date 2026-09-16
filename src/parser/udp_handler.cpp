/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** udp_handler.cpp
*/

#include "parser/udp_handler.hpp"
#include "parser/bytes_utils.hpp"

namespace sniffer {

    namespace {
        constexpr uint8_t kProtocolUdp = 17;
        constexpr std::size_t kUdpHeaderLen = 8;
    } // namespace

    void UdpHandler::handle(const uint8_t* data, std::size_t len, PacketBuilder& builder) {
        if (!builder.ipv4().has_value() || builder.ipv4()->protocol != kProtocolUdp) {
            if (next_) {
                next_->handle(data, len, builder);
            }
            return;
        }

        if (data == nullptr || len < kUdpHeaderLen) {
            return;
        }

        TransportHeader transport{};
        transport.src_port = bytes::readUint16BE(data);
        transport.dst_port = bytes::readUint16BE(data + 2);

        builder.setTransport(transport);
        builder.setPayload(std::vector<uint8_t>(data + kUdpHeaderLen, data + len));
    }

} // namespace sniffer
