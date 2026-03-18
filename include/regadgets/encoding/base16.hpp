#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::string encode_b16(std::span<const byte> input,
                       std::string_view alphabet = "0123456789ABCDEF");
bytes decode_b16(std::string_view input,
                 std::string_view alphabet = "0123456789ABCDEF");

} // namespace regadgets
