#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

class WindowsRand {
public:
  explicit WindowsRand(std::uint32_t seed = 1);
  void seed(std::uint32_t value);
  std::uint32_t next();
  std::vector<std::uint32_t> sequence(std::size_t count);

private:
  std::uint32_t state_ = 1;
};

} // namespace regadgets
