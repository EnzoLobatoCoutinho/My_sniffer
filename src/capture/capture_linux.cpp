/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** capture_linux.cpp
*/

#include "capture/capture_linux.hpp"
#include "parser/bytes_utils.hpp"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>
#include <vector>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

namespace sniffer {

    namespace {
        constexpr std::size_t kReadBufferSize = 65536;

        uint16_t allProtocolsNetworkOrder() {
            static_assert(ETH_P_ALL >= 0 && ETH_P_ALL <= 0xFFFF, "ETH_P_ALL must fit in 16 bits");
            const uint8_t wire[2] = {
                static_cast<uint8_t>((ETH_P_ALL >> 8) & 0xFF),
                static_cast<uint8_t>(ETH_P_ALL & 0xFF),
            };
            return bytes::readUint16BE(wire);
        }
    } // namespace

    CaptureLinux::CaptureLinux(std::string interfaceName)
        : interface_name_(std::move(interfaceName)) {}

    CaptureLinux::~CaptureLinux() {
        stop();
        if (socket_fd_ >= 0) {
            ::close(socket_fd_);
        }
    }

    void CaptureLinux::start(PacketCallback callback) {
        socket_fd_ = ::socket(AF_PACKET, SOCK_RAW, allProtocolsNetworkOrder());
        if (socket_fd_ < 0) {
            throw std::runtime_error(
                "CaptureLinux: failed to open raw socket on '" + interface_name_ +
                "' (requires root/CAP_NET_RAW): " + std::strerror(errno));
        }

        const unsigned int ifindex = ::if_nametoindex(interface_name_.c_str());
        if (ifindex == 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
            throw std::runtime_error("CaptureLinux: unknown network interface '" + interface_name_ + "'");
        }

        sockaddr_ll addr{};
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = allProtocolsNetworkOrder();
        addr.sll_ifindex = static_cast<int>(ifindex);

        if (::bind(socket_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            const std::string reason = std::strerror(errno);
            ::close(socket_fd_);
            socket_fd_ = -1;
            throw std::runtime_error("CaptureLinux: failed to bind to '" + interface_name_ + "': " + reason);
        }

        std::vector<uint8_t> buffer(kReadBufferSize);
        running_ = true;

        while (running_) {
            const ssize_t received = ::recv(socket_fd_, buffer.data(), buffer.size(), 0);
            if (received < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (received == 0) {
                continue;
            }
            callback(buffer.data(), static_cast<std::size_t>(received));
        }
    }

    void CaptureLinux::stop() {
        running_ = false;
        if (socket_fd_ >= 0) {
            ::shutdown(socket_fd_, SHUT_RDWR);
        }
    }

} // namespace sniffer
