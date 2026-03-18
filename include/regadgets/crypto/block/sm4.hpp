#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::array<byte, 16> SM4_encrypt(std::span<const byte, 16> block,
                                 std::span<const byte, 16> key);
std::array<byte, 16> SM4_decrypt(std::span<const byte, 16> block,
                                 std::span<const byte, 16> key);
bytes sm4_ecb_encrypt(std::span<const byte> input,
                      std::span<const byte, 16> key);
bytes sm4_ecb_decrypt(std::span<const byte> input,
                      std::span<const byte, 16> key);
bytes sm4_cbc_encrypt(std::span<const byte> input,
                      std::span<const byte, 16> key,
                      std::span<const byte, 16> iv);
bytes sm4_cbc_decrypt(std::span<const byte> input,
                      std::span<const byte, 16> key,
                      std::span<const byte, 16> iv);

} // namespace regadgets
