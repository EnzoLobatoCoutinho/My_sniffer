#include "analysis/analysis_engine.hpp"
#include "core/packet_builder.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

using sniffer::Alert;
using sniffer::AnalysisEngine;
using sniffer::IAnalyzer;
using sniffer::Packet;
using sniffer::PacketBuilder;

namespace {

class AlwaysAlertsAnalyzer : public IAnalyzer {
    public:
        explicit AlwaysAlertsAnalyzer(std::string message) : message_(std::move(message)) {}

        std::vector<Alert> onPacket(const Packet&) override {
            return {Alert{"Always", message_}};
        }

    private:
        std::string message_;
};

class NeverAlertsAnalyzer : public IAnalyzer {
    public:
        std::vector<Alert> onPacket(const Packet&) override {
            return {};
        }
};

} // namespace

TEST(AnalysisEngineTest, AggregatesAlertsFromAllAnalyzers) {
    AnalysisEngine engine;
    engine.addAnalyzer(std::make_unique<AlwaysAlertsAnalyzer>("first"));
    engine.addAnalyzer(std::make_unique<NeverAlertsAnalyzer>());
    engine.addAnalyzer(std::make_unique<AlwaysAlertsAnalyzer>("second"));

    auto pkt = PacketBuilder().build();
    auto alerts = engine.onPacket(pkt);

    ASSERT_EQ(alerts.size(), 2u);
    EXPECT_EQ(alerts[0].message, "first");
    EXPECT_EQ(alerts[1].message, "second");
}

TEST(AnalysisEngineTest, ReturnsEmptyWithNoAnalyzers) {
    AnalysisEngine engine;
    auto pkt = PacketBuilder().build();

    EXPECT_TRUE(engine.onPacket(pkt).empty());
}
