/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** event_bus.hpp
*/

#ifndef MY_SNIFFER_CORE_EVENT_BUS_HPP_
    #define MY_SNIFFER_CORE_EVENT_BUS_HPP_

#include "core/packet.hpp"

#include <functional>
#include <vector>

namespace sniffer {

class EventBus {
    public:
        using Handler = std::function<void(const Packet&)>;

        void subscribe(Handler handler);
        void publish(const Packet& packet) const;

    private:
        std::vector<Handler> subscribers_;
};

} // namespace sniffer

#endif // MY_SNIFFER_CORE_EVENT_BUS_HPP_
