#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

using sniffer::EthernetHeader;
using sniffer::Ipv4Header;
using sniffer::PacketBuilder;
using sniffer::TransportHeader;

TEST(PacketBuilderTest, BuildsPacketFromAllLayers) {
    const auto now = std::chrono::system_clock::now();

    EthernetHeader eth{};
    eth.ethertype = 0x0800;

    Ipv4Header ip{};
    ip.protocol = 17;

    TransportHeader transport{};
    transport.src_port = 53;
    transport.dst_port = 12345;

    auto pkt = PacketBuilder()
                   .setTimestamp(now)
                   .setLength(64)
                   .setEthernet(eth)
                   .setIpv4(ip)
                   .setTransport(transport)
                   .setPayload({0xAA, 0xBB})
                   .build();

    EXPECT_EQ(pkt.timestamp(), now);
    EXPECT_EQ(pkt.length(), 64u);
    ASSERT_TRUE(pkt.ethernet().has_value());
    EXPECT_EQ(pkt.ethernet()->ethertype, 0x0800);
    ASSERT_TRUE(pkt.ipv4().has_value());
    EXPECT_EQ(pkt.ipv4()->protocol, 17);
    ASSERT_TRUE(pkt.transport().has_value());
    EXPECT_EQ(pkt.transport()->src_port, 53);
    EXPECT_EQ(pkt.payload(), (std::vector<uint8_t>{0xAA, 0xBB}));
}

TEST(PacketBuilderTest, LeavesUnsetLayersEmpty) {
    auto pkt = PacketBuilder().setLength(10).build();

    EXPECT_EQ(pkt.length(), 10u);
    EXPECT_FALSE(pkt.ethernet().has_value());
    EXPECT_FALSE(pkt.ipv4().has_value());
    EXPECT_FALSE(pkt.transport().has_value());
    EXPECT_TRUE(pkt.payload().empty());
}

TEST(PacketBuilderTest, SettingLayerAgainOverwritesPrevious) {
    Ipv4Header first{};
    first.ttl = 1;
    Ipv4Header second{};
    second.ttl = 64;

    auto pkt = PacketBuilder().setIpv4(first).setIpv4(second).build();

    ASSERT_TRUE(pkt.ipv4().has_value());
    EXPECT_EQ(pkt.ipv4()->ttl, 64);
}

TEST(PacketBuilderTest, GettersExposeStateBeforeBuild) {
    Ipv4Header ip{};
    ip.protocol = 6;

    PacketBuilder builder;
    builder.setIpv4(ip);

    ASSERT_TRUE(builder.ipv4().has_value());
    EXPECT_EQ(builder.ipv4()->protocol, 6);
    EXPECT_FALSE(builder.ethernet().has_value());
    EXPECT_FALSE(builder.transport().has_value());
    EXPECT_TRUE(builder.payload().empty());
}
