/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** tcp_handler.cpp
*/

#include "parser/tcp_handler.hpp"
#include "parser/bytes_utils.hpp"

namespace sniffer {

    namespace {
        constexpr uint8_t kProtocolTcp = 6;
        constexpr std::size_t kTcpMinHeaderLen = 20;
    } // namespace

    void TcpHandler::handle(const uint8_t* data, std::size_t len, PacketBuilder& builder) {
        if (!builder.ipv4().has_value() || builder.ipv4()->protocol != kProtocolTcp) {
            if (next_) {
                next_->handle(data, len, builder);
            }
            return;
        }

        if (data == nullptr || len < kTcpMinHeaderLen) {
            return;
        }

        const auto dataOffset = static_cast<std::size_t>((data[12] >> 4) & 0x0F);
        const std::size_t headerLen = dataOffset * 4;

        if (headerLen < kTcpMinHeaderLen || headerLen > len) {
            return;
        }

        TransportHeader transport{};
        transport.src_port = bytes::readUint16BE(data);
        transport.dst_port = bytes::readUint16BE(data + 2);

        builder.setTransport(transport);
        builder.setPayload(std::vector<uint8_t>(data + headerLen, data + len));
    }

} // namespace sniffer
