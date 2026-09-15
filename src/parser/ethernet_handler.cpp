/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** ethernet_handler.cpp
*/

#include "parser/ethernet_handler.hpp"
#include "parser/bytes_utils.hpp"

#include <algorithm>

namespace sniffer {

    namespace {
        constexpr std::size_t kEthernetHeaderLen = 14;
        constexpr uint16_t kEthertypeIpv4 = 0x0800;
    } // namespace

    void EthernetHandler::handle(const uint8_t* data, std::size_t len, PacketBuilder& builder) {
        if (data == nullptr || len < kEthernetHeaderLen) {
            return;
        }

        EthernetHeader eth{};
        std::copy(data, data + 6, eth.dst_mac.begin());
        std::copy(data + 6, data + 12, eth.src_mac.begin());
        eth.ethertype = bytes::readUint16BE(data + 12);

        builder.setEthernet(eth);

        if (eth.ethertype == kEthertypeIpv4 && next_) {
            next_->handle(data + kEthernetHeaderLen, len - kEthernetHeaderLen, builder);
        }
    }

} // namespace sniffer
