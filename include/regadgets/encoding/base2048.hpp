#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

#ifdef REGADGETS_ENABLE_BASE2048
std::u32string encode_b2048(std::span<const byte> input,
                            std::span<const char32_t> alphabet);
bytes decode_b2048(std::u32string_view input,
                   std::span<const char32_t> alphabet);
#endif

} // namespace regadgets
