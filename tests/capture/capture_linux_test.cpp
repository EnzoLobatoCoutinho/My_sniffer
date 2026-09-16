#include "capture/capture_linux.hpp"

#include <gtest/gtest.h>

using sniffer::CaptureLinux;

// No root privileges or real network interface are assumed available in
// the test environment, so this only exercises the error paths that are
// reachable either way (socket() denied without CAP_NET_RAW, or the
// interface simply not existing) - never the blocking capture loop.
TEST(CaptureLinuxTest, ThrowsOnUnknownInterface) {
    CaptureLinux capture("this-interface-does-not-exist-xyz");

    EXPECT_THROW(capture.start([](const uint8_t*, std::size_t) {}), std::runtime_error);
}

TEST(CaptureLinuxTest, StopBeforeStartDoesNotCrash) {
    CaptureLinux capture("this-interface-does-not-exist-xyz");

    EXPECT_NO_THROW(capture.stop());
}
