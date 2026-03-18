#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::array<std::uint32_t, 2> xtea_encrypt(std::array<std::uint32_t, 2> block,
                                          std::array<std::uint32_t, 4> key,
                                          std::uint32_t rounds = 32);
std::array<std::uint32_t, 2> xtea_decrypt(std::array<std::uint32_t, 2> block,
                                          std::array<std::uint32_t, 4> key,
                                          std::uint32_t rounds = 32);
bytes xtea_encrypt(std::span<const byte> input,
                   std::array<std::uint32_t, 4> key, std::uint32_t rounds = 32);
bytes xtea_decrypt(std::span<const byte> input,
                   std::array<std::uint32_t, 4> key, std::uint32_t rounds = 32);

} // namespace regadgets
