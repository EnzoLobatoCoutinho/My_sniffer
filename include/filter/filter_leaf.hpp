/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** filter_leaf.hpp
*/

#ifndef MY_SNIFFER_FILTER_FILTER_LEAF_HPP_
    #define MY_SNIFFER_FILTER_FILTER_LEAF_HPP_

#include "filter/ifilter.hpp"

#include <cstdint>

namespace sniffer {

// Matches when the source or the destination IPv4 address equals ip.
// Never matches a packet without an IPv4 layer.
class IpFilter : public IFilter {
    public:
        explicit IpFilter(uint32_t ip);

        bool matches(const Packet& packet) const override;

    private:
        uint32_t ip_;
};

// Matches when the source or the destination port equals port.
// Never matches a packet without a transport layer.
class PortFilter : public IFilter {
    public:
        explicit PortFilter(uint16_t port);

        bool matches(const Packet& packet) const override;

    private:
        uint16_t port_;
};

// Matches when the IPv4 protocol field equals protocol (6 = TCP, 17 = UDP,
// 1 = ICMP...). Never matches a packet without an IPv4 layer.
class ProtocolFilter : public IFilter {
    public:
        explicit ProtocolFilter(uint8_t protocol);

        bool matches(const Packet& packet) const override;

    private:
        uint8_t protocol_;
};

} // namespace sniffer

#endif // MY_SNIFFER_FILTER_FILTER_LEAF_HPP_
