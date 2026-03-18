#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::string
encode_b58(std::span<const byte> input,
           std::string_view alphabet =
               "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
bytes decode_b58(
    std::string_view input,
    std::string_view alphabet =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");

} // namespace regadgets
