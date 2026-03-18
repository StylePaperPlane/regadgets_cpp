#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

bytes from_string(std::string_view input);
std::string to_string(std::span<const byte> input);
std::string to_hex(std::span<const byte> input, bool uppercase = false);
bytes from_hex(std::string_view hex);

std::uint16_t bytes_to_word(std::span<const byte> input,
                            bool little_endian = true);
std::uint32_t bytes_to_dword(std::span<const byte> input,
                             bool little_endian = true);
std::uint64_t bytes_to_qword(std::span<const byte> input,
                             bool little_endian = true);
bytes word_to_bytes(std::uint16_t value, bool little_endian = true);
bytes dword_to_bytes(std::uint32_t value, bool little_endian = true);
bytes qword_to_bytes(std::uint64_t value, bool little_endian = true);
bytes pack_dword(std::span<const std::uint32_t> values,
                 bool little_endian = true);
std::vector<std::uint32_t> unpack_dword(std::span<const byte> input,
                                        bool little_endian = true);
std::uint32_t bswap32(std::uint32_t value) noexcept;

} // namespace regadgets
