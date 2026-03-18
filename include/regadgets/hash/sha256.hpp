#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

bytes sha256(std::span<const byte> input);

} // namespace regadgets
