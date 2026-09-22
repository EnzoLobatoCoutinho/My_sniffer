/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** ifilter.hpp
*/

#ifndef MY_SNIFFER_FILTER_IFILTER_HPP_
    #define MY_SNIFFER_FILTER_IFILTER_HPP_

#include "core/packet.hpp"

namespace sniffer {

class IFilter {
    public:
        virtual ~IFilter() = default;

        virtual bool matches(const Packet& packet) const = 0;
};

} // namespace sniffer

#endif // MY_SNIFFER_FILTER_IFILTER_HPP_
