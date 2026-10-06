/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** capture_windows.hpp
*/

#ifndef MY_SNIFFER_CAPTURE_CAPTURE_WINDOWS_HPP_
    #define MY_SNIFFER_CAPTURE_CAPTURE_WINDOWS_HPP_

#include "capture/icapture.hpp"

#include <atomic>
#include <string>

struct pcap;
using pcap_t = struct pcap;

namespace sniffer {

class CaptureWindows : public ICapture {
    public:
        explicit CaptureWindows(std::string interfaceName);
        ~CaptureWindows() override;

        CaptureWindows(const CaptureWindows&) = delete;
        CaptureWindows& operator=(const CaptureWindows&) = delete;

        void start(PacketCallback callback) override;
        void stop() override;

    private:
        std::string interface_name_;
        pcap_t* handle_ = nullptr;
        std::atomic<bool> running_{false};
};

} // namespace sniffer

#endif // MY_SNIFFER_CAPTURE_CAPTURE_WINDOWS_HPP_
