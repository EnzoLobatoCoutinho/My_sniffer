/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** ethernet_handler.hpp
*/

#ifndef MY_SNIFFER_PARSER_ETHERNET_HANDLER_HPP_
    #define MY_SNIFFER_PARSER_ETHERNET_HANDLER_HPP_

#include "parser/iparser_handler.hpp"

namespace sniffer {

class EthernetHandler : public IParserHandler {
    public:
        void handle(const uint8_t* data, std::size_t len, PacketBuilder& builder) override;
};

} // namespace sniffer

#endif // MY_SNIFFER_PARSER_ETHERNET_HANDLER_HPP_
