#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::string encode_b85(std::span<const byte> input,
                       std::string_view alphabet = {});
bytes decode_b85(std::string_view input, std::string_view alphabet = {});

} // namespace regadgets
