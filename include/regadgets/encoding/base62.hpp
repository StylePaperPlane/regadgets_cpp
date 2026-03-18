#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::string encode_b62(
    std::span<const byte> input,
    std::string_view alphabet =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
bytes decode_b62(
    std::string_view input,
    std::string_view alphabet =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

} // namespace regadgets
