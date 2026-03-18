#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

template <typename T> constexpr T rol(T value, unsigned int shift) noexcept {
  constexpr unsigned int width = sizeof(T) * 8U;
  const unsigned int amount = shift % width;
  return static_cast<T>((value << amount) |
                        (value >> ((width - amount) % width)));
}

template <typename T> constexpr T ror(T value, unsigned int shift) noexcept {
  constexpr unsigned int width = sizeof(T) * 8U;
  const unsigned int amount = shift % width;
  return static_cast<T>((value >> amount) |
                        (value << ((width - amount) % width)));
}

bytes bxor(std::span<const byte> lhs, std::span<const byte> rhs);
bytes bxor_cycle(std::span<const byte> lhs, std::span<const byte> rhs);
bytes bxorr_enc(std::span<const byte> input, byte seed = 0);
bytes bxorr_dec(std::span<const byte> input, byte seed = 0);
bytes bxorl_enc(std::span<const byte> input, byte seed = 0);
bytes bxorl_dec(std::span<const byte> input, byte seed = 0);

} // namespace regadgets
