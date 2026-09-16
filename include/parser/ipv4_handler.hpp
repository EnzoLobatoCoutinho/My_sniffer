/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** ipv4_handler.hpp
*/

#ifndef MY_SNIFFER_PARSER_IPV4_HANDLER_HPP_
    #define MY_SNIFFER_PARSER_IPV4_HANDLER_HPP_

#include "parser/iparser_handler.hpp"

namespace sniffer {

class Ipv4Handler : public IParserHandler {
    public:
        void handle(const uint8_t* data, std::size_t len, PacketBuilder& builder) override;
};

} // namespace sniffer

#endif // MY_SNIFFER_PARSER_IPV4_HANDLER_HPP_
