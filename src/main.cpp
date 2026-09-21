/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** main.cpp
*/

#include "core/event_bus.hpp"
#include "core/packet_builder.hpp"
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

} // namespace

int main(int argc, char** argv) {
#ifdef MY_SNIFFER_LINUX
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <interface>" << std::endl;
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
    bus.subscribe(printPacket);

    sniffer::CaptureLinux capture(argv[1]);

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
