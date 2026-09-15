#include "core/event_bus.hpp"
#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

using sniffer::EventBus;
using sniffer::PacketBuilder;

TEST(EventBusTest, PublishNotifiesAllSubscribers) {
    EventBus bus;
    int first_calls = 0;
    int second_calls = 0;

    bus.subscribe([&](const auto&) { ++first_calls; });
    bus.subscribe([&](const auto&) { ++second_calls; });

    auto pkt = PacketBuilder().setLength(1).build();
    bus.publish(pkt);

    EXPECT_EQ(first_calls, 1);
    EXPECT_EQ(second_calls, 1);
}

TEST(EventBusTest, SubscriberReceivesThePublishedPacket) {
    EventBus bus;
    std::size_t received_length = 0;

    bus.subscribe([&](const auto& pkt) { received_length = pkt.length(); });

    auto pkt = PacketBuilder().setLength(42).build();
    bus.publish(pkt);

    EXPECT_EQ(received_length, 42u);
}

TEST(EventBusTest, PublishWithNoSubscribersDoesNothing) {
    EventBus bus;
    auto pkt = PacketBuilder().setLength(1).build();

    EXPECT_NO_THROW(bus.publish(pkt));
}
