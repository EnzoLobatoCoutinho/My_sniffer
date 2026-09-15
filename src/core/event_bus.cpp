/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** event_bus.cpp
*/

#include "core/event_bus.hpp"

#include <utility>

namespace sniffer {

    void EventBus::subscribe(Handler handler) {
        subscribers_.push_back(std::move(handler));
    }

    void EventBus::publish(const Packet& packet) const {
        for (const auto& handler : subscribers_) {
            handler(packet);
        }
    }

} // namespace sniffer
