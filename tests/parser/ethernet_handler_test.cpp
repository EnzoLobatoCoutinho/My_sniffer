#include "parser/ethernet_handler.hpp"

#include <gtest/gtest.h>

using sniffer::EthernetHandler;
using sniffer::IParserHandler;
using sniffer::PacketBuilder;

namespace {

class RecordingHandler : public IParserHandler {
    public:
        void handle(const uint8_t* data, std::size_t len, PacketBuilder& builder) override {
            (void)data;
            (void)builder;
            called = true;
            received_len = len;
        }

        bool called = false;
        std::size_t received_len = 0;
};

} // namespace

TEST(EthernetHandlerTest, ParsesHeaderAndForwardsToNextOnIpv4) {
    const uint8_t frame[] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // dst mac
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // src mac
        0x08, 0x00,                          // ethertype = IPv4
        0x01, 0x02, 0x03, 0x04,              // fake payload
    };

    auto next = std::make_shared<RecordingHandler>();
    EthernetHandler handler;
    handler.setNext(next);

    PacketBuilder builder;
    handler.handle(frame, sizeof(frame), builder);
    auto pkt = builder.build();

    ASSERT_TRUE(pkt.ethernet().has_value());
    EXPECT_EQ(pkt.ethernet()->ethertype, 0x0800);
    EXPECT_EQ(pkt.ethernet()->dst_mac, (std::array<uint8_t, 6>{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}));
    EXPECT_EQ(pkt.ethernet()->src_mac, (std::array<uint8_t, 6>{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}));

    EXPECT_TRUE(next->called);
    EXPECT_EQ(next->received_len, 4u);
}

TEST(EthernetHandlerTest, DoesNotForwardWhenEthertypeIsNotIpv4) {
    const uint8_t frame[] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x08, 0x06,  // ethertype = ARP
        0x01, 0x02,
    };

    auto next = std::make_shared<RecordingHandler>();
    EthernetHandler handler;
    handler.setNext(next);

    PacketBuilder builder;
    handler.handle(frame, sizeof(frame), builder);
    auto pkt = builder.build();

    ASSERT_TRUE(pkt.ethernet().has_value());
    EXPECT_EQ(pkt.ethernet()->ethertype, 0x0806);
    EXPECT_FALSE(next->called);
}

TEST(EthernetHandlerTest, IgnoresTruncatedFrameWithoutCrashing) {
    const uint8_t frame[] = {0xAA, 0xBB, 0xCC};  // way too short

    auto next = std::make_shared<RecordingHandler>();
    EthernetHandler handler;
    handler.setNext(next);

    PacketBuilder builder;
    EXPECT_NO_THROW(handler.handle(frame, sizeof(frame), builder));

    auto pkt = builder.build();
    EXPECT_FALSE(pkt.ethernet().has_value());
    EXPECT_FALSE(next->called);
}
