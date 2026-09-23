#include "parser/tcp_handler.hpp"

#include <gtest/gtest.h>

using sniffer::Ipv4Header;
using sniffer::PacketBuilder;
using sniffer::TcpHandler;

TEST(TcpHandlerTest, ParsesHeaderAndPayloadWhenProtocolIsTcp) {
    const uint8_t segment[] = {
        0x00, 0x50,              // src port = 80
        0x1F, 0x90,              // dst port = 8080
        0x00, 0x00, 0x00, 0x01,  // sequence number
        0x00, 0x00, 0x00, 0x00,  // ack number
        0x50, 0x18,              // data offset = 5 (20 bytes), flags
        0xFF, 0xFF,              // window size
        0x00, 0x00,              // checksum
        0x00, 0x00,              // urgent pointer
        0xCA, 0xFE,              // payload
    };

    Ipv4Header ip{};
    ip.protocol = 6;

    PacketBuilder builder;
    builder.setIpv4(ip);

    TcpHandler handler;
    handler.handle(segment, sizeof(segment), builder);
    auto pkt = builder.build();

    ASSERT_TRUE(pkt.transport().has_value());
    EXPECT_EQ(pkt.transport()->src_port, 80);
    EXPECT_EQ(pkt.transport()->dst_port, 8080);
    EXPECT_EQ(pkt.payload(), (std::vector<uint8_t>{0xCA, 0xFE}));
}

TEST(TcpHandlerTest, ForwardsUntouchedWhenProtocolIsNotTcp) {
    Ipv4Header ip{};
    ip.protocol = 17;  // UDP

    PacketBuilder builder;
    builder.setIpv4(ip);

    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    TcpHandler handler;
    handler.handle(data, sizeof(data), builder);

    auto pkt = builder.build();
    EXPECT_FALSE(pkt.transport().has_value());
}

TEST(TcpHandlerTest, IgnoresTruncatedSegmentWithoutCrashing) {
    Ipv4Header ip{};
    ip.protocol = 6;

    PacketBuilder builder;
    builder.setIpv4(ip);

    const uint8_t data[] = {0x00, 0x50, 0x1F};  // way too short

    TcpHandler handler;
    EXPECT_NO_THROW(handler.handle(data, sizeof(data), builder));

    auto pkt = builder.build();
    EXPECT_FALSE(pkt.transport().has_value());
}
