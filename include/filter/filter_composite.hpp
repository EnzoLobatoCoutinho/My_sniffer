/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** filter_composite.hpp
*/

#ifndef MY_SNIFFER_FILTER_FILTER_COMPOSITE_HPP_
    #define MY_SNIFFER_FILTER_FILTER_COMPOSITE_HPP_

#include "filter/ifilter.hpp"

#include <memory>
#include <vector>

namespace sniffer {

class AndFilter : public IFilter {
    public:
        void add(std::shared_ptr<IFilter> filter);

        bool matches(const Packet& packet) const override;

    private:
        std::vector<std::shared_ptr<IFilter>> children_;
};

class OrFilter : public IFilter {
    public:
        void add(std::shared_ptr<IFilter> filter);

        bool matches(const Packet& packet) const override;

    private:
        std::vector<std::shared_ptr<IFilter>> children_;
};

class NotFilter : public IFilter {
    public:
        explicit NotFilter(std::shared_ptr<IFilter> filter);

        bool matches(const Packet& packet) const override;

    private:
        std::shared_ptr<IFilter> filter_;
};

} // namespace sniffer

#endif // MY_SNIFFER_FILTER_FILTER_COMPOSITE_HPP_
