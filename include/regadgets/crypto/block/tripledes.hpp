#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

bytes tripledes_encrypt(std::span<const byte> input, std::span<const byte> key,
                        block_mode mode = block_mode::ecb,
                        std::span<const byte> iv = {});
bytes tripledes_decrypt(std::span<const byte> input, std::span<const byte> key,
                        block_mode mode = block_mode::ecb,
                        std::span<const byte> iv = {});

} // namespace regadgets
