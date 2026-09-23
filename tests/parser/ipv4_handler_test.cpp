#include "parser/ipv4_handler.hpp"

#include <gtest/gtest.h>

using sniffer::IParserHandler;
using sniffer::Ipv4Handler;
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

TEST(Ipv4HandlerTest, ParsesHeaderAndForwardsRemainder) {
    const uint8_t packet[] = {
        0x45, 0x00, 0x00, 0x28,  // version/IHL=5 (20 bytes), DSCP, total length
        0x00, 0x00, 0x00, 0x00,  // identification, flags/fragment
        0x40, 0x06, 0x00, 0x00,  // TTL=64, protocol=TCP(6), checksum
        0x0A, 0x00, 0x00, 0x01,  // src ip = 10.0.0.1
        0x0A, 0x00, 0x00, 0x02,  // dst ip = 10.0.0.2
        0xDE, 0xAD, 0xBE, 0xEF,  // fake transport payload
    };

    auto next = std::make_shared<RecordingHandler>();
    Ipv4Handler handler;
    handler.setNext(next);

    PacketBuilder builder;
    handler.handle(packet, sizeof(packet), builder);
    auto pkt = builder.build();

    ASSERT_TRUE(pkt.ipv4().has_value());
    EXPECT_EQ(pkt.ipv4()->ttl, 64);
    EXPECT_EQ(pkt.ipv4()->protocol, 6);
    EXPECT_EQ(pkt.ipv4()->src_ip, 0x0A000001u);
    EXPECT_EQ(pkt.ipv4()->dst_ip, 0x0A000002u);

    EXPECT_TRUE(next->called);
    EXPECT_EQ(next->received_len, 4u);
}

TEST(Ipv4HandlerTest, SkipsOptionsWhenIhlIsLarger) {
    const uint8_t packet[] = {
        0x46, 0x00, 0x00, 0x00,  // version/IHL=6 (24 bytes)
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,  // protocol=UDP(17)
        0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02,
        0x01, 0x02, 0x03, 0x04,  // 4 bytes of IP options
        0xAA, 0xBB,              // fake transport payload
    };

    auto next = std::make_shared<RecordingHandler>();
    Ipv4Handler handler;
    handler.setNext(next);

    PacketBuilder builder;
    handler.handle(packet, sizeof(packet), builder);
    auto pkt = builder.build();

    ASSERT_TRUE(pkt.ipv4().has_value());
    EXPECT_EQ(pkt.ipv4()->protocol, 17);
    EXPECT_TRUE(next->called);
    EXPECT_EQ(next->received_len, 2u);  // 26 total - 24 byte header = 2
}

TEST(Ipv4HandlerTest, IgnoresTruncatedHeaderWithoutCrashing) {
    const uint8_t packet[] = {0x45, 0x00, 0x00};  // way too short

    auto next = std::make_shared<RecordingHandler>();
    Ipv4Handler handler;
    handler.setNext(next);

    PacketBuilder builder;
    EXPECT_NO_THROW(handler.handle(packet, sizeof(packet), builder));

    auto pkt = builder.build();
    EXPECT_FALSE(pkt.ipv4().has_value());
    EXPECT_FALSE(next->called);
}

TEST(Ipv4HandlerTest, IgnoresInconsistentIhlWithoutCrashing) {
    const uint8_t packet[] = {
        0x4F, 0x00, 0x00, 0x00,  // IHL=15 -> claims a 60-byte header
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02,
    };  // only 20 bytes actually available

    auto next = std::make_shared<RecordingHandler>();
    Ipv4Handler handler;
    handler.setNext(next);

    PacketBuilder builder;
    EXPECT_NO_THROW(handler.handle(packet, sizeof(packet), builder));

    auto pkt = builder.build();
    EXPECT_FALSE(pkt.ipv4().has_value());
    EXPECT_FALSE(next->called);
}
