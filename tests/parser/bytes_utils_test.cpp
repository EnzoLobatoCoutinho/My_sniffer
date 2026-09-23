#include "parser/bytes_utils.hpp"

#include <gtest/gtest.h>

using namespace sniffer::bytes;

TEST(BytesUtilsTest, ReadUint16BE) {
    const uint8_t data[] = {0x12, 0x34};
    EXPECT_EQ(readUint16BE(data), 0x1234);
}

TEST(BytesUtilsTest, ReadUint32BE) {
    const uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
    EXPECT_EQ(readUint32BE(data), 0x12345678u);
}

TEST(BytesUtilsTest, MacToString) {
    std::array<uint8_t, 6> mac{0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22};
    EXPECT_EQ(macToString(mac), "aa:bb:cc:00:11:22");
}

TEST(BytesUtilsTest, Ipv4ToString) {
    EXPECT_EQ(ipv4ToString(0x0A000001), "10.0.0.1");
    EXPECT_EQ(ipv4ToString(0xFFFFFFFF), "255.255.255.255");
}

TEST(BytesUtilsTest, ParseIpv4Valid) {
    EXPECT_EQ(parseIpv4("10.0.0.1"), 0x0A000001u);
    EXPECT_EQ(parseIpv4("255.255.255.255"), 0xFFFFFFFFu);
    EXPECT_EQ(parseIpv4("0.0.0.0"), 0x00000000u);
}

TEST(BytesUtilsTest, ParseIpv4RoundTripsWithIpv4ToString) {
    EXPECT_EQ(ipv4ToString(*parseIpv4("192.168.1.42")), "192.168.1.42");
}

TEST(BytesUtilsTest, ParseIpv4RejectsMalformedInput) {
    EXPECT_EQ(parseIpv4(""), std::nullopt);
    EXPECT_EQ(parseIpv4("10.0.0"), std::nullopt);
    EXPECT_EQ(parseIpv4("10.0.0.1.2"), std::nullopt);
    EXPECT_EQ(parseIpv4("10.0.0."), std::nullopt);
    EXPECT_EQ(parseIpv4(".10.0.0.1"), std::nullopt);
    EXPECT_EQ(parseIpv4("256.0.0.1"), std::nullopt);
    EXPECT_EQ(parseIpv4("10.0.0.a"), std::nullopt);
    EXPECT_EQ(parseIpv4("10..0.1"), std::nullopt);
}
