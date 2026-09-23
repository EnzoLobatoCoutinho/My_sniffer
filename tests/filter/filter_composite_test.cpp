#include "filter/filter_composite.hpp"
#include "filter/filter_leaf.hpp"
#include "core/packet.hpp"
#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

using sniffer::AndFilter;
using sniffer::Ipv4Header;
using sniffer::NotFilter;
using sniffer::OrFilter;
using sniffer::Packet;
using sniffer::PacketBuilder;
using sniffer::PortFilter;
using sniffer::ProtocolFilter;
using sniffer::TransportHeader;

namespace {

Packet makeTcpPacketOnPort443() {
    Ipv4Header ip{};
    ip.src_ip = 0x0A000001;
    ip.dst_ip = 0x0A000002;
    ip.protocol = 6;

    TransportHeader transport{};
    transport.src_port = 12345;
    transport.dst_port = 443;

    return PacketBuilder().setIpv4(ip).setTransport(transport).build();
}

} // namespace

TEST(AndFilterTest, MatchesOnlyWhenAllChildrenMatch) {
    auto pkt = makeTcpPacketOnPort443();

    AndFilter allMatch;
    allMatch.add(std::make_shared<ProtocolFilter>(6));
    allMatch.add(std::make_shared<PortFilter>(443));
    EXPECT_TRUE(allMatch.matches(pkt));

    AndFilter oneFails;
    oneFails.add(std::make_shared<ProtocolFilter>(6));
    oneFails.add(std::make_shared<PortFilter>(80));
    EXPECT_FALSE(oneFails.matches(pkt));
}

TEST(AndFilterTest, MatchesEverythingWhenEmpty) {
    auto pkt = makeTcpPacketOnPort443();

    AndFilter empty;
    EXPECT_TRUE(empty.matches(pkt));
}

TEST(OrFilterTest, MatchesWhenAtLeastOneChildMatches) {
    auto pkt = makeTcpPacketOnPort443();

    OrFilter anyMatch;
    anyMatch.add(std::make_shared<PortFilter>(80));
    anyMatch.add(std::make_shared<PortFilter>(443));
    EXPECT_TRUE(anyMatch.matches(pkt));

    OrFilter noneMatch;
    noneMatch.add(std::make_shared<PortFilter>(80));
    noneMatch.add(std::make_shared<PortFilter>(53));
    EXPECT_FALSE(noneMatch.matches(pkt));
}

TEST(OrFilterTest, MatchesNothingWhenEmpty) {
    auto pkt = makeTcpPacketOnPort443();

    OrFilter empty;
    EXPECT_FALSE(empty.matches(pkt));
}

TEST(NotFilterTest, InvertsWrappedFilter) {
    auto pkt = makeTcpPacketOnPort443();

    NotFilter notPort443(std::make_shared<PortFilter>(443));
    EXPECT_FALSE(notPort443.matches(pkt));

    NotFilter notPort80(std::make_shared<PortFilter>(80));
    EXPECT_TRUE(notPort80.matches(pkt));
}

TEST(CompositeFilterTest, CanNestAndAndOr) {
    // (protocol == TCP) AND (port == 443 OR port == 8443)
    auto pkt = makeTcpPacketOnPort443();

    auto portOr = std::make_shared<OrFilter>();
    portOr->add(std::make_shared<PortFilter>(443));
    portOr->add(std::make_shared<PortFilter>(8443));

    AndFilter combined;
    combined.add(std::make_shared<ProtocolFilter>(6));
    combined.add(portOr);

    EXPECT_TRUE(combined.matches(pkt));
}
