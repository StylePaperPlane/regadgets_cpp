#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::string
encode_b32(std::span<const byte> input,
           std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
bytes decode_b32(
    std::string_view input,
    std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");

} // namespace regadgets
