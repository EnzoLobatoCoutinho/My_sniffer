#include "analysis/rate_spike_analyzer.hpp"
#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

using sniffer::Ipv4Header;
using sniffer::Packet;
using sniffer::PacketBuilder;
using sniffer::RateSpikeAnalyzer;

namespace {

Packet makeIpv4Packet(uint32_t srcIp, std::chrono::system_clock::time_point ts) {
    Ipv4Header ip{};
    ip.src_ip = srcIp;
    ip.dst_ip = 0x0A000002;
    return PacketBuilder().setIpv4(ip).setTimestamp(ts).build();
}

} // namespace

TEST(RateSpikeAnalyzerTest, AlertsWhenThresholdExceededWithinWindow) {
    RateSpikeAnalyzer analyzer(std::chrono::milliseconds(1000), 3);
    const auto base = std::chrono::system_clock::now();

    for (int i = 0; i < 3; ++i) {
        auto pkt = makeIpv4Packet(0x0A000001, base + std::chrono::milliseconds(i * 10));
        EXPECT_TRUE(analyzer.onPacket(pkt).empty());
    }

    auto pkt4 = makeIpv4Packet(0x0A000001, base + std::chrono::milliseconds(40));
    auto alerts = analyzer.onPacket(pkt4);
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].analyzer, "RateSpikeAnalyzer");
}

TEST(RateSpikeAnalyzerTest, DoesNotReAlertWhileStillOverThreshold) {
    RateSpikeAnalyzer analyzer(std::chrono::milliseconds(1000), 1);
    const auto base = std::chrono::system_clock::now();

    EXPECT_TRUE(analyzer.onPacket(makeIpv4Packet(0x0A000001, base)).empty());

    auto alerts = analyzer.onPacket(makeIpv4Packet(0x0A000001, base + std::chrono::milliseconds(10)));
    EXPECT_EQ(alerts.size(), 1u);

    EXPECT_TRUE(analyzer.onPacket(makeIpv4Packet(0x0A000001, base + std::chrono::milliseconds(20))).empty());
}

TEST(RateSpikeAnalyzerTest, DoesNotMixDifferentSources) {
    RateSpikeAnalyzer analyzer(std::chrono::milliseconds(1000), 1);
    const auto base = std::chrono::system_clock::now();

    EXPECT_TRUE(analyzer.onPacket(makeIpv4Packet(0x0A000001, base)).empty());
    EXPECT_TRUE(analyzer.onPacket(makeIpv4Packet(0x0A000002, base)).empty());
}

TEST(RateSpikeAnalyzerTest, OldTimestampsAgeOutOfWindow) {
    RateSpikeAnalyzer analyzer(std::chrono::milliseconds(100), 1);
    const auto base = std::chrono::system_clock::now();

    EXPECT_TRUE(analyzer.onPacket(makeIpv4Packet(0x0A000001, base)).empty());
    EXPECT_TRUE(
        analyzer.onPacket(makeIpv4Packet(0x0A000001, base + std::chrono::milliseconds(500))).empty());
}

TEST(RateSpikeAnalyzerTest, IgnoresPacketWithoutIpv4Layer) {
    RateSpikeAnalyzer analyzer(std::chrono::milliseconds(1000), 0);
    auto pkt = PacketBuilder().build();

    EXPECT_TRUE(analyzer.onPacket(pkt).empty());
}
