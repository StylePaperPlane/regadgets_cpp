#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::string encode_b91(std::span<const byte> input,
                       std::string_view alphabet =
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy"
                           "z0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"");
bytes decode_b91(std::string_view input,
                 std::string_view alphabet =
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234"
                     "56789!#$%&()*+,./:;<=>?@[]^_`{|}~\"");

} // namespace regadgets
