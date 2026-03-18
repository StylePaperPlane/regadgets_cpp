#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::string encode_b64(
    std::span<const byte> input,
    std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
bytes decode_b64(
    std::string_view input,
    std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

} // namespace regadgets
