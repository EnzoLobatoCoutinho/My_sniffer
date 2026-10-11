#include "analysis/port_protocol_analyzer.hpp"
#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

using sniffer::Packet;
using sniffer::PacketBuilder;
using sniffer::PortProtocolAnalyzer;
using sniffer::TransportHeader;

namespace {

Packet makePacket(uint16_t dstPort, const std::vector<uint8_t>& payload) {
    TransportHeader transport{};
    transport.src_port = 54321;
    transport.dst_port = dstPort;
    return PacketBuilder().setTransport(transport).setPayload(payload).build();
}

std::vector<uint8_t> toBytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

} // namespace

TEST(PortProtocolAnalyzerTest, AcceptsRealHttpOnPort80) {
    PortProtocolAnalyzer analyzer;

    EXPECT_TRUE(analyzer.onPacket(makePacket(80, toBytes("GET / HTTP/1.1\r\n"))).empty());
}

TEST(PortProtocolAnalyzerTest, FlagsNonHttpOnPort80) {
    PortProtocolAnalyzer analyzer;

    auto alerts = analyzer.onPacket(makePacket(80, toBytes("SSH-2.0-OpenSSH_9.0\r\n")));
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].analyzer, "PortProtocolAnalyzer");
}

TEST(PortProtocolAnalyzerTest, AcceptsTlsHandshakeOnPort443) {
    PortProtocolAnalyzer analyzer;

    EXPECT_TRUE(analyzer.onPacket(makePacket(443, {0x16, 0x03, 0x03, 0x00, 0x10})).empty());
}

TEST(PortProtocolAnalyzerTest, FlagsNonTlsOnPort443) {
    PortProtocolAnalyzer analyzer;

    EXPECT_EQ(analyzer.onPacket(makePacket(443, toBytes("plaintext tunnel"))).size(), 1u);
}

TEST(PortProtocolAnalyzerTest, IgnoresUnconfiguredPorts) {
    PortProtocolAnalyzer analyzer;

    EXPECT_TRUE(analyzer.onPacket(makePacket(9999, toBytes("anything goes here"))).empty());
}

TEST(PortProtocolAnalyzerTest, IgnoresEmptyPayload) {
    PortProtocolAnalyzer analyzer;

    EXPECT_TRUE(analyzer.onPacket(makePacket(80, {})).empty());
}

TEST(PortProtocolAnalyzerTest, CustomExpectationCanBeAdded) {
    PortProtocolAnalyzer analyzer;
    analyzer.addExpectation(53, [](const std::vector<uint8_t>& payload) {
        return payload.size() >= 12; // minimal DNS header length
    });

    EXPECT_TRUE(analyzer.onPacket(makePacket(53, std::vector<uint8_t>(12, 0))).empty());
    EXPECT_EQ(analyzer.onPacket(makePacket(53, std::vector<uint8_t>(4, 0))).size(), 1u);
}
