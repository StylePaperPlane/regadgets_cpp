#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

bytes salsa20_crypt(std::span<const byte> key, std::span<const byte> nonce,
                    std::uint64_t counter, std::span<const byte> input,
                    std::size_t rounds = 20);

} // namespace regadgets
