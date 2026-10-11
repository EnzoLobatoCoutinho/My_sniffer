#include "analysis/foreign_ip_analyzer.hpp"
#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

using sniffer::ForeignIpAnalyzer;
using sniffer::Ipv4Header;
using sniffer::Packet;
using sniffer::PacketBuilder;

namespace {

Packet makePacketToDst(uint32_t dstIp) {
    Ipv4Header ip{};
    ip.src_ip = 0x0A000001; // 10.0.0.1
    ip.dst_ip = dstIp;
    return PacketBuilder().setIpv4(ip).build();
}

} // namespace

TEST(ForeignIpAnalyzerTest, DoesNotFlagPrivateOrLoopbackDestinations) {
    ForeignIpAnalyzer analyzer({});

    EXPECT_TRUE(analyzer.onPacket(makePacketToDst(0x0A000002)).empty()); // 10.0.0.2
    EXPECT_TRUE(analyzer.onPacket(makePacketToDst(0xC0A80001)).empty()); // 192.168.0.1
    EXPECT_TRUE(analyzer.onPacket(makePacketToDst(0xAC100001)).empty()); // 172.16.0.1
    EXPECT_TRUE(analyzer.onPacket(makePacketToDst(0x7F000001)).empty()); // 127.0.0.1
}

TEST(ForeignIpAnalyzerTest, FlagsUnauthorizedForeignDestination) {
    ForeignIpAnalyzer analyzer({});

    auto alerts = analyzer.onPacket(makePacketToDst(0x08080808)); // 8.8.8.8
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].analyzer, "ForeignIpAnalyzer");
}

TEST(ForeignIpAnalyzerTest, DoesNotFlagAllowlistedForeignDestination) {
    ForeignIpAnalyzer analyzer({0x08080808});

    EXPECT_TRUE(analyzer.onPacket(makePacketToDst(0x08080808)).empty());
}

TEST(ForeignIpAnalyzerTest, AlertsOnlyOncePerUniqueDestination) {
    ForeignIpAnalyzer analyzer({});

    EXPECT_EQ(analyzer.onPacket(makePacketToDst(0x08080808)).size(), 1u);
    EXPECT_TRUE(analyzer.onPacket(makePacketToDst(0x08080808)).empty());
    EXPECT_EQ(analyzer.onPacket(makePacketToDst(0x08080404)).size(), 1u);
}

TEST(ForeignIpAnalyzerTest, IgnoresPacketWithoutIpv4Layer) {
    ForeignIpAnalyzer analyzer({});

    EXPECT_TRUE(analyzer.onPacket(PacketBuilder().build()).empty());
}
