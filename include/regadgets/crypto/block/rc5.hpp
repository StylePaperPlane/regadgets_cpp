#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

bytes rc5_encrypt(std::span<const byte> input, std::span<const byte> key,
                  std::uint32_t word_bits = 32, std::uint32_t rounds = 12);
bytes rc5_decrypt(std::span<const byte> input, std::span<const byte> key,
                  std::uint32_t word_bits = 32, std::uint32_t rounds = 12);

} // namespace regadgets
