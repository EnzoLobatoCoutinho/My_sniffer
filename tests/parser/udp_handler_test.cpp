#include "parser/udp_handler.hpp"

#include <gtest/gtest.h>

using sniffer::Ipv4Header;
using sniffer::PacketBuilder;
using sniffer::UdpHandler;

TEST(UdpHandlerTest, ParsesHeaderAndPayloadWhenProtocolIsUdp) {
    const uint8_t datagram[] = {
        0x00, 0x35,  // src port = 53
        0xC3, 0x50,  // dst port = 50000
        0x00, 0x0A,  // length
        0x00, 0x00,  // checksum
        0xDE, 0xAD,  // payload
    };

    Ipv4Header ip{};
    ip.protocol = 17;

    PacketBuilder builder;
    builder.setIpv4(ip);

    UdpHandler handler;
    handler.handle(datagram, sizeof(datagram), builder);
    auto pkt = builder.build();

    ASSERT_TRUE(pkt.transport().has_value());
    EXPECT_EQ(pkt.transport()->src_port, 53);
    EXPECT_EQ(pkt.transport()->dst_port, 50000);
    EXPECT_EQ(pkt.payload(), (std::vector<uint8_t>{0xDE, 0xAD}));
}

TEST(UdpHandlerTest, ForwardsUntouchedWhenProtocolIsNotUdp) {
    Ipv4Header ip{};
    ip.protocol = 6;  // TCP

    PacketBuilder builder;
    builder.setIpv4(ip);

    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    UdpHandler handler;
    handler.handle(data, sizeof(data), builder);

    auto pkt = builder.build();
    EXPECT_FALSE(pkt.transport().has_value());
}

TEST(UdpHandlerTest, IgnoresTruncatedDatagramWithoutCrashing) {
    Ipv4Header ip{};
    ip.protocol = 17;

    PacketBuilder builder;
    builder.setIpv4(ip);

    const uint8_t data[] = {0x00, 0x35};  // way too short

    UdpHandler handler;
    EXPECT_NO_THROW(handler.handle(data, sizeof(data), builder));

    auto pkt = builder.build();
    EXPECT_FALSE(pkt.transport().has_value());
}
