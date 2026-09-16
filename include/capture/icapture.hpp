/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** icapture.hpp
*/

#ifndef MY_SNIFFER_CAPTURE_ICAPTURE_HPP_
    #define MY_SNIFFER_CAPTURE_ICAPTURE_HPP_

#include <cstddef>
#include <cstdint>
#include <functional>

namespace sniffer {

class ICapture {
    public:
        using PacketCallback = std::function<void(const uint8_t* data, std::size_t len)>;

        virtual ~ICapture() = default;

        virtual void start(PacketCallback callback) = 0;
        virtual void stop() = 0;
};

} // namespace sniffer

#endif // MY_SNIFFER_CAPTURE_ICAPTURE_HPP_
