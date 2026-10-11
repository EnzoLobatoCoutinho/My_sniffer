#include "storage/logger.hpp"
#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

using sniffer::Alert;
using sniffer::Ipv4Header;
using sniffer::Logger;
using sniffer::PacketBuilder;
using sniffer::TransportHeader;

namespace {

class LoggerTest : public ::testing::Test {
    protected:
        void SetUp() override {
            std::remove(path_.c_str());
        }

        void TearDown() override {
            std::remove(path_.c_str());
        }

        std::string readFile() const {
            std::ifstream in(path_);
            std::ostringstream oss;
            oss << in.rdbuf();
            return oss.str();
        }

        const std::string path_ = "logger_test_output.log";
};

} // namespace

TEST_F(LoggerTest, ThrowsWhenPathCannotBeOpened) {
    EXPECT_THROW(Logger logger("/nonexistent_dir_xyz/cannot_create.log"), std::runtime_error);
}

TEST_F(LoggerTest, LogsPacketWithIpv4AndTransport) {
    {
        Logger logger(path_);

        Ipv4Header ip{};
        ip.src_ip = 0x0A000001;
        ip.dst_ip = 0x0A000002;
        ip.protocol = 6;

        TransportHeader transport{};
        transport.src_port = 12345;
        transport.dst_port = 443;

        auto pkt = PacketBuilder().setLength(66).setIpv4(ip).setTransport(transport).build();
        logger.logPacket(pkt);
    }

    const std::string content = readFile();
    EXPECT_NE(content.find("66 bytes"), std::string::npos);
    EXPECT_NE(content.find("10.0.0.1 -> 10.0.0.2"), std::string::npos);
    EXPECT_NE(content.find("12345 -> 443"), std::string::npos);
}

TEST_F(LoggerTest, LogsPacketWithoutLayers) {
    {
        Logger logger(path_);
        auto pkt = PacketBuilder().setLength(10).build();
        logger.logPacket(pkt);
    }

    const std::string content = readFile();
    EXPECT_NE(content.find("10 bytes"), std::string::npos);
}

TEST_F(LoggerTest, LogsAlert) {
    {
        Logger logger(path_);
        logger.logAlert(Alert{"TestAnalyzer", "something suspicious"});
    }

    const std::string content = readFile();
    EXPECT_NE(content.find("[ALERT] (TestAnalyzer) something suspicious"), std::string::npos);
}

TEST_F(LoggerTest, AppendsAcrossMultipleInstances) {
    {
        Logger logger(path_);
        logger.logAlert(Alert{"A", "first"});
    }
    {
        Logger logger(path_);
        logger.logAlert(Alert{"B", "second"});
    }

    const std::string content = readFile();
    EXPECT_NE(content.find("first"), std::string::npos);
    EXPECT_NE(content.find("second"), std::string::npos);
}
