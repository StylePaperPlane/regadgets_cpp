#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

class GLIBCRand {
public:
  explicit GLIBCRand(std::uint32_t seed = 1);
  void seed(std::uint32_t value);
  std::uint32_t next();
  std::vector<std::uint32_t> sequence(std::size_t count);

private:
  std::array<std::uint32_t, 344> state_{};
  std::size_t index_ = 0;
};

} // namespace regadgets
