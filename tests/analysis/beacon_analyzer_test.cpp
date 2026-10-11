#include "analysis/beacon_analyzer.hpp"
#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

#include <vector>

using sniffer::Alert;
using sniffer::BeaconAnalyzer;
using sniffer::Ipv4Header;
using sniffer::Packet;
using sniffer::PacketBuilder;
using sniffer::TransportHeader;

namespace {

Packet makeFlowPacket(uint32_t srcIp, uint32_t dstIp, uint16_t dstPort,
                       std::chrono::system_clock::time_point ts) {
    Ipv4Header ip{};
    ip.src_ip = srcIp;
    ip.dst_ip = dstIp;

    TransportHeader transport{};
    transport.dst_port = dstPort;

    return PacketBuilder().setIpv4(ip).setTransport(transport).setTimestamp(ts).build();
}

} // namespace

TEST(BeaconAnalyzerTest, AlertsOnRegularIntervals) {
    BeaconAnalyzer analyzer(3, 0.1);
    const auto base = std::chrono::system_clock::now();
    const auto step = std::chrono::milliseconds(1000);

    EXPECT_TRUE(analyzer.onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base)).empty());

    std::vector<Alert> lastAlerts;
    for (int i = 1; i <= 3; ++i) {
        lastAlerts = analyzer.onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base + step * i));
    }

    ASSERT_EQ(lastAlerts.size(), 1u);
    EXPECT_EQ(lastAlerts[0].analyzer, "BeaconAnalyzer");
}

TEST(BeaconAnalyzerTest, DoesNotAlertOnIrregularIntervals) {
    BeaconAnalyzer analyzer(3, 0.1);
    const auto base = std::chrono::system_clock::now();

    EXPECT_TRUE(analyzer.onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base)).empty());
    EXPECT_TRUE(analyzer
                    .onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base + std::chrono::milliseconds(500)))
                    .empty());
    EXPECT_TRUE(analyzer
                    .onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base + std::chrono::milliseconds(1800)))
                    .empty());
    EXPECT_TRUE(analyzer
                    .onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base + std::chrono::milliseconds(5000)))
                    .empty());
}

TEST(BeaconAnalyzerTest, DoesNotMixDifferentFlows) {
    BeaconAnalyzer analyzer(2, 0.1);
    const auto base = std::chrono::system_clock::now();
    const auto step = std::chrono::milliseconds(1000);

    EXPECT_TRUE(analyzer.onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base)).empty());
    EXPECT_TRUE(analyzer.onPacket(makeFlowPacket(0x0A000002, 0x08080808, 443, base + step)).empty());
}

TEST(BeaconAnalyzerTest, IgnoresPacketMissingLayers) {
    BeaconAnalyzer analyzer(2, 0.1);

    EXPECT_TRUE(analyzer.onPacket(PacketBuilder().build()).empty());
}

TEST(BeaconAnalyzerTest, DoesNotReAlertWhileStillRegular) {
    BeaconAnalyzer analyzer(2, 0.1);
    const auto base = std::chrono::system_clock::now();
    const auto step = std::chrono::milliseconds(1000);

    EXPECT_TRUE(analyzer.onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base)).empty());
    EXPECT_TRUE(analyzer.onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base + step)).empty());
    EXPECT_EQ(analyzer.onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base + step * 2)).size(), 1u);
    EXPECT_TRUE(analyzer.onPacket(makeFlowPacket(0x0A000001, 0x08080808, 443, base + step * 3)).empty());
}
