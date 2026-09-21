/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** capture_linux.hpp
*/

#ifndef MY_SNIFFER_CAPTURE_CAPTURE_LINUX_HPP_
    #define MY_SNIFFER_CAPTURE_CAPTURE_LINUX_HPP_

#include "capture/icapture.hpp"

#include <atomic>
#include <string>

namespace sniffer {

class CaptureLinux : public ICapture {
    public:
        explicit CaptureLinux(std::string interfaceName);
        ~CaptureLinux() override;

        CaptureLinux(const CaptureLinux&) = delete;
        CaptureLinux& operator=(const CaptureLinux&) = delete;

        void start(PacketCallback callback) override;
        void stop() override;

    private:
        std::string interface_name_;
        int socket_fd_ = -1;
        std::atomic<bool> running_{false};
};

} // namespace sniffer

#endif // MY_SNIFFER_CAPTURE_CAPTURE_LINUX_HPP_
