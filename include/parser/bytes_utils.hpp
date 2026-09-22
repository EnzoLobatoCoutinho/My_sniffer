/*
** EPITECH PROJECT, 2026
** My_sniffer
** File description:
** bytes_utils.hpp
*/

#ifndef MY_SNIFFER_PARSER_BYTES_UTILS_HPP_
    #define MY_SNIFFER_PARSER_BYTES_UTILS_HPP_

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace sniffer::bytes {

// Reads a big-endian (network byte order) 16-bit value starting at data.
// Caller must guarantee at least 2 readable bytes.
uint16_t readUint16BE(const uint8_t* data);

// Reads a big-endian (network byte order) 32-bit value starting at data.
// Caller must guarantee at least 4 readable bytes.
uint32_t readUint32BE(const uint8_t* data);

// Formats a 6-byte MAC address as "aa:bb:cc:dd:ee:ff".
std::string macToString(const std::array<uint8_t, 6>& mac);

// Formats an IPv4 address (as produced by readUint32BE) as "a.b.c.d".
std::string ipv4ToString(uint32_t ip);

// Parses "a.b.c.d" (each octet 0-255, exactly 4 of them) into the same
// representation readUint32BE/ipv4ToString use. Returns std::nullopt for
// anything malformed instead of throwing.
std::optional<uint32_t> parseIpv4(const std::string& text);

} // namespace sniffer::bytes

#endif // MY_SNIFFER_PARSER_BYTES_UTILS_HPP_
