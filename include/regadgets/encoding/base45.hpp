#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::string encode_b45(std::span<const byte> input,
                       std::string_view alphabet =
                           "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:");
bytes decode_b45(std::string_view input,
                 std::string_view alphabet =
                     "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:");

} // namespace regadgets
