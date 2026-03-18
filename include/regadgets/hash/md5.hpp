#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

bytes md5(std::span<const byte> input);

} // namespace regadgets
