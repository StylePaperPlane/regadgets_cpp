#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

bytes xxtea_encrypt(std::span<const byte> input,
                    std::array<std::uint32_t, 4> key,
                    xxtea_options options = {});
bytes xxtea_decrypt(std::span<const byte> input,
                    std::array<std::uint32_t, 4> key,
                    xxtea_options options = {});

} // namespace regadgets
