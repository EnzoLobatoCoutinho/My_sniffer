#include "filter/filter_leaf.hpp"
#include "core/packet.hpp"
#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

using sniffer::IpFilter;
using sniffer::Ipv4Header;
using sniffer::Packet;
using sniffer::PacketBuilder;
using sniffer::PortFilter;
using sniffer::ProtocolFilter;
using sniffer::TransportHeader;

namespace {

Packet makePacket() {
    Ipv4Header ip{};
    ip.src_ip = 0x0A000001;  // 10.0.0.1
    ip.dst_ip = 0x0A000002;  // 10.0.0.2
    ip.protocol = 6;

    TransportHeader transport{};
    transport.src_port = 12345;
    transport.dst_port = 443;

    return PacketBuilder().setIpv4(ip).setTransport(transport).build();
}

} // namespace

TEST(IpFilterTest, MatchesSourceOrDestination) {
    auto pkt = makePacket();

    EXPECT_TRUE(IpFilter(0x0A000001).matches(pkt));
    EXPECT_TRUE(IpFilter(0x0A000002).matches(pkt));
    EXPECT_FALSE(IpFilter(0x0A000003).matches(pkt));
}

TEST(IpFilterTest, DoesNotMatchWhenNoIpv4Layer) {
    auto pkt = PacketBuilder().build();

    EXPECT_FALSE(IpFilter(0x0A000001).matches(pkt));
}

TEST(PortFilterTest, MatchesSourceOrDestination) {
    auto pkt = makePacket();

    EXPECT_TRUE(PortFilter(12345).matches(pkt));
    EXPECT_TRUE(PortFilter(443).matches(pkt));
    EXPECT_FALSE(PortFilter(80).matches(pkt));
}

TEST(PortFilterTest, DoesNotMatchWhenNoTransportLayer) {
    auto pkt = PacketBuilder().build();

    EXPECT_FALSE(PortFilter(80).matches(pkt));
}

TEST(ProtocolFilterTest, MatchesIpv4Protocol) {
    auto pkt = makePacket();

    EXPECT_TRUE(ProtocolFilter(6).matches(pkt));
    EXPECT_FALSE(ProtocolFilter(17).matches(pkt));
}

TEST(ProtocolFilterTest, DoesNotMatchWhenNoIpv4Layer) {
    auto pkt = PacketBuilder().build();

    EXPECT_FALSE(ProtocolFilter(6).matches(pkt));
}
