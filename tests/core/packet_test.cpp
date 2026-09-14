#include "core/packet.hpp"

#include <gtest/gtest.h>

using sniffer::EthernetHeader;
using sniffer::Ipv4Header;
using sniffer::Packet;
using sniffer::TransportHeader;

TEST(PacketTest, StoresAllLayersWhenPresent) {
    const auto now = std::chrono::system_clock::now();

    EthernetHeader eth{};
    eth.src_mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    eth.dst_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    eth.ethertype = 0x0800;

    Ipv4Header ip{};
    ip.src_ip = 0x0A000001;
    ip.dst_ip = 0x0A000002;
    ip.protocol = 6;
    ip.ttl = 64;

    TransportHeader transport{};
    transport.src_port = 12345;
    transport.dst_port = 443;

    std::vector<uint8_t> payload{0x01, 0x02, 0x03};

    Packet pkt(now, 128, eth, ip, transport, payload);

    EXPECT_EQ(pkt.timestamp(), now);
    EXPECT_EQ(pkt.length(), 128u);

    ASSERT_TRUE(pkt.ethernet().has_value());
    EXPECT_EQ(pkt.ethernet()->ethertype, 0x0800);

    ASSERT_TRUE(pkt.ipv4().has_value());
    EXPECT_EQ(pkt.ipv4()->protocol, 6);
    EXPECT_EQ(pkt.ipv4()->ttl, 64);

    ASSERT_TRUE(pkt.transport().has_value());
    EXPECT_EQ(pkt.transport()->src_port, 12345);
    EXPECT_EQ(pkt.transport()->dst_port, 443);

    EXPECT_EQ(pkt.payload(), payload);
}

TEST(PacketTest, LeavesMissingLayersEmpty) {
    const auto now = std::chrono::system_clock::now();

    Packet pkt(now, 42, std::nullopt, std::nullopt, std::nullopt, {});

    EXPECT_FALSE(pkt.ethernet().has_value());
    EXPECT_FALSE(pkt.ipv4().has_value());
    EXPECT_FALSE(pkt.transport().has_value());
    EXPECT_TRUE(pkt.payload().empty());
}
