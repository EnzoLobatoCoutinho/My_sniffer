/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** capture_windows.cpp
*/

#include "capture/capture_windows.hpp"

#include <stdexcept>
#include <utility>

#include <pcap.h>

namespace sniffer {

    namespace {
        constexpr int kSnapshotLength = 65536;

        constexpr int kPromiscuousMode = 1;

        constexpr int kReadTimeoutMs = 1000;
    } // namespace

    CaptureWindows::CaptureWindows(std::string interfaceName)
        : interface_name_(std::move(interfaceName)) {}

    CaptureWindows::~CaptureWindows() {
        stop();
        if (handle_ != nullptr) {
            pcap_close(handle_);
        }
    }

    void CaptureWindows::start(PacketCallback callback) {
        char errbuf[PCAP_ERRBUF_SIZE] = {};

        handle_ = pcap_open_live(interface_name_.c_str(), kSnapshotLength, kPromiscuousMode,
                                  kReadTimeoutMs, errbuf);
        if (handle_ == nullptr) {
            throw std::runtime_error(
                "CaptureWindows: failed to open '" + interface_name_ +
                "' (requires the Npcap driver installed and an Administrator terminal): " + errbuf);
        }

        running_ = true;

        while (running_) {
            pcap_pkthdr* header = nullptr;
            const u_char* data = nullptr;
            const int result = pcap_next_ex(handle_, &header, &data);

            if (result == 1) {
                callback(reinterpret_cast<const uint8_t*>(data), header->caplen);
            } else if (result == 0) {
                continue;
            } else {
                break;
            }
        }
    }

    void CaptureWindows::stop() {
        running_ = false;
    }

} // namespace sniffer
