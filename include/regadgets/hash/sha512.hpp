#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

bytes sha512(std::span<const byte> input);

} // namespace regadgets
