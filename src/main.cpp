/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** main.cpp
*/

#include "core/event_bus.hpp"
#include "core/packet_builder.hpp"
#include "filter/filter_composite.hpp"
#include "filter/filter_leaf.hpp"
#include "parser/bytes_utils.hpp"
#include "parser/ethernet_handler.hpp"
#include "parser/ipv4_handler.hpp"
#include "parser/tcp_handler.hpp"
#include "parser/udp_handler.hpp"

#ifdef MY_SNIFFER_LINUX
    #include "capture/capture_linux.hpp"
#endif

#include <iostream>
#include <memory>
#include <optional>
#include <string>

namespace {

    void printPacket(const sniffer::Packet& pkt) {
        std::cout << "[" << pkt.length() << " bytes]";
        if (pkt.ipv4().has_value()) {
            std::cout << " " << sniffer::bytes::ipv4ToString(pkt.ipv4()->src_ip)
                       << " -> " << sniffer::bytes::ipv4ToString(pkt.ipv4()->dst_ip)
                       << " proto=" << static_cast<int>(pkt.ipv4()->protocol);
        }
        if (pkt.transport().has_value()) {
            std::cout << " " << pkt.transport()->src_port << " -> " << pkt.transport()->dst_port;
        }
        std::cout << std::endl;
    }

    struct CliOptions {
        std::string interface;
        std::shared_ptr<sniffer::AndFilter> filter = std::make_shared<sniffer::AndFilter>();
    };

    std::optional<CliOptions> parseArgs(int argc, char** argv) {
        if (argc < 2) {
            return std::nullopt;
        }

        CliOptions options;
        options.interface = argv[1];

        for (int i = 2; i < argc; ++i) {
            const std::string arg = argv[i];
            const bool needsValue = (arg == "--port" || arg == "--ip" || arg == "--protocol");

            if (needsValue && i + 1 >= argc) {
                std::cerr << "my_sniffer: missing value for " << arg << std::endl;
                return std::nullopt;
            }

            if (arg == "--port") {
                const std::string value = argv[++i];
                std::size_t consumed = 0;
                int port = -1;
                try {
                    port = std::stoi(value, &consumed);
                } catch (const std::exception&) {
                    consumed = 0;
                }
                if (consumed != value.size() || port < 0 || port > 0xFFFF) {
                    std::cerr << "my_sniffer: invalid port '" << value << "'" << std::endl;
                    return std::nullopt;
                }
                options.filter->add(std::make_shared<sniffer::PortFilter>(static_cast<uint16_t>(port)));
            } else if (arg == "--ip") {
                const std::string value = argv[++i];
                const auto ip = sniffer::bytes::parseIpv4(value);
                if (!ip.has_value()) {
                    std::cerr << "my_sniffer: invalid IP address '" << value << "'" << std::endl;
                    return std::nullopt;
                }
                options.filter->add(std::make_shared<sniffer::IpFilter>(*ip));
            } else if (arg == "--protocol") {
                const std::string value = argv[++i];
                std::size_t consumed = 0;
                int protocol = -1;
                try {
                    protocol = std::stoi(value, &consumed);
                } catch (const std::exception&) {
                    consumed = 0;
                }
                if (consumed != value.size() || protocol < 0 || protocol > 0xFF) {
                    std::cerr << "my_sniffer: invalid protocol '" << value << "'" << std::endl;
                    return std::nullopt;
                }
                options.filter->add(std::make_shared<sniffer::ProtocolFilter>(static_cast<uint8_t>(protocol)));
            } else {
                std::cerr << "my_sniffer: unknown argument '" << arg << "'" << std::endl;
                return std::nullopt;
            }
        }

        return options;
    }

} // namespace

int main(int argc, char** argv) {
#ifdef MY_SNIFFER_LINUX
    const auto options = parseArgs(argc, argv);
    if (!options.has_value()) {
        std::cerr << "usage: " << argv[0]
                   << " <interface> [--port PORT] [--ip A.B.C.D] [--protocol N]" << std::endl;
        return 1;
    }

    auto eth = std::make_shared<sniffer::EthernetHandler>();
    auto ipv4 = std::make_shared<sniffer::Ipv4Handler>();
    auto tcp = std::make_shared<sniffer::TcpHandler>();
    auto udp = std::make_shared<sniffer::UdpHandler>();
    eth->setNext(ipv4);
    ipv4->setNext(tcp);
    tcp->setNext(udp);

    sniffer::EventBus bus;
    const auto filter = options->filter;
    bus.subscribe([filter](const sniffer::Packet& pkt) {
        if (filter->matches(pkt)) {
            printPacket(pkt);
        }
    });

    sniffer::CaptureLinux capture(options->interface);

    try {
        capture.start([&](const uint8_t* data, std::size_t len) {
            sniffer::PacketBuilder builder;
            builder.setLength(len);
            eth->handle(data, len, builder);
            bus.publish(builder.build());
        });
    } catch (const std::exception& e) {
        std::cerr << "my_sniffer: " << e.what() << std::endl;
        return 1;
    }

    return 0;
#else
    (void)argc;
    (void)argv;
    std::cerr << "my_sniffer: capture is not yet implemented on this platform" << std::endl;
    return 1;
#endif
}
