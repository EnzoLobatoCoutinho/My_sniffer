/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** filter_composite.cpp
*/

#include "filter/filter_composite.hpp"

#include <utility>

namespace sniffer {

    void AndFilter::add(std::shared_ptr<IFilter> filter) {
        children_.push_back(std::move(filter));
    }

    bool AndFilter::matches(const Packet& packet) const {
        for (const auto& child : children_) {
            if (!child->matches(packet)) {
                return false;
            }
        }
        return true;
    }

    void OrFilter::add(std::shared_ptr<IFilter> filter) {
        children_.push_back(std::move(filter));
    }

    bool OrFilter::matches(const Packet& packet) const {
        for (const auto& child : children_) {
            if (child->matches(packet)) {
                return true;
            }
        }
        return false;
    }

    NotFilter::NotFilter(std::shared_ptr<IFilter> filter) : filter_(std::move(filter)) {}

    bool NotFilter::matches(const Packet& packet) const {
        return !filter_->matches(packet);
    }

} // namespace sniffer
