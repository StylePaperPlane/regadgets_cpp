#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

std::vector<double> dct_transform(std::span<const double> input);
std::vector<double> idct_transform(std::span<const double> input);

} // namespace regadgets
