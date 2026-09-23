/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** filter_leaf.cpp
*/

#include "filter/filter_leaf.hpp"

namespace sniffer {

    IpFilter::IpFilter(uint32_t ip) : ip_(ip) {}

    bool IpFilter::matches(const Packet& packet) const {
        if (!packet.ipv4().has_value()) {
            return false;
        }
        return packet.ipv4()->src_ip == ip_ || packet.ipv4()->dst_ip == ip_;
    }

    PortFilter::PortFilter(uint16_t port) : port_(port) {}

    bool PortFilter::matches(const Packet& packet) const {
        if (!packet.transport().has_value()) {
            return false;
        }
        return packet.transport()->src_port == port_ || packet.transport()->dst_port == port_;
    }

    ProtocolFilter::ProtocolFilter(uint8_t protocol) : protocol_(protocol) {}

    bool ProtocolFilter::matches(const Packet& packet) const {
        if (!packet.ipv4().has_value()) {
            return false;
        }
        return packet.ipv4()->protocol == protocol_;
    }

} // namespace sniffer
