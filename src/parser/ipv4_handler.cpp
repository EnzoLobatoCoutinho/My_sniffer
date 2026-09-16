/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** ipv4_handler.cpp
*/

#include "parser/ipv4_handler.hpp"
#include "parser/bytes_utils.hpp"

namespace sniffer {

    namespace {
        constexpr std::size_t kIpv4MinHeaderLen = 20;
    } // namespace

    void Ipv4Handler::handle(const uint8_t* data, std::size_t len, PacketBuilder& builder) {
        if (data == nullptr || len < kIpv4MinHeaderLen) {
            return;
        }

        const auto ihl = static_cast<std::size_t>(data[0] & 0x0F);
        const std::size_t headerLen = ihl * 4;

        if (headerLen < kIpv4MinHeaderLen || headerLen > len) {
            return;
        }

        Ipv4Header ip{};
        ip.ttl = data[8];
        ip.protocol = data[9];
        ip.src_ip = bytes::readUint32BE(data + 12);
        ip.dst_ip = bytes::readUint32BE(data + 16);

        builder.setIpv4(ip);

        if (next_) {
            next_->handle(data + headerLen, len - headerLen, builder);
        }
    }

} // namespace sniffer
