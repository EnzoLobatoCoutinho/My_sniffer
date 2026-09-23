/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** iparser_handler.hpp
*/

#ifndef MY_SNIFFER_PARSER_IPARSER_HANDLER_HPP_
    #define MY_SNIFFER_PARSER_IPARSER_HANDLER_HPP_

#include "core/packet_builder.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace sniffer {

class IParserHandler {
    public:
        virtual ~IParserHandler() = default;

        void setNext(std::shared_ptr<IParserHandler> next) {
            next_ = std::move(next);
        }

        virtual void handle(const uint8_t* data, std::size_t len, PacketBuilder& builder) {
            if (next_) {
                next_->handle(data, len, builder);
            }
        }

    protected:
        std::shared_ptr<IParserHandler> next_;
};

} // namespace sniffer

#endif // MY_SNIFFER_PARSER_IPARSER_HANDLER_HPP_
