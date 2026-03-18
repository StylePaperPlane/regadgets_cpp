#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::string encode_b92(
    std::span<const byte> input,
    std::string_view alphabet = "!#$%&'()*+,-./"
                                "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ["
                                "\\]^_abcdefghijklmnopqrstuvwxyz{|}~");
bytes decode_b92(
    std::string_view input,
    std::string_view alphabet = "!#$%&'()*+,-./"
                                "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ["
                                "\\]^_abcdefghijklmnopqrstuvwxyz{|}~");

} // namespace regadgets
