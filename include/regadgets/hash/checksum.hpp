#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::uint32_t crc32(std::span<const byte> input,
                    std::uint32_t seed = 0xFFFFFFFFu);
std::uint64_t crc64(std::span<const byte> input,
                    std::uint64_t seed = 0xFFFFFFFFFFFFFFFFull);
std::uint32_t adler32(std::span<const byte> input);

} // namespace regadgets
