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
