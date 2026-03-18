#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::pair<bytes, bytes> generate_sbox(std::span<const byte> permutation);
bytes sbox_transform(std::span<const byte> input, std::span<const byte> sbox);

} // namespace regadgets
