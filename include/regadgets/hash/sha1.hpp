#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

bytes sha1(std::span<const byte> input);

} // namespace regadgets
