#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

class MT19937 {
public:
  static constexpr std::size_t state_size = 624;

  explicit MT19937(std::uint32_t seed = 5489u);
  void seed(std::uint32_t value);
  std::uint32_t next();
  std::vector<std::uint32_t> sequence(std::size_t count);

private:
  std::array<std::uint32_t, state_size> state_{};
  std::size_t index_ = state_size;
};

class MT19937Predictor {
public:
  static constexpr std::size_t state_size = MT19937::state_size;

  void reset();
  void submit(std::uint32_t sample);
  void submit(std::span<const std::uint32_t> samples);
  [[nodiscard]] bool ready() const noexcept;
  [[nodiscard]] std::size_t samples_collected() const noexcept;
  std::uint32_t next();
  std::vector<std::uint32_t> sequence(std::size_t count);

private:
  std::array<std::uint32_t, state_size> state_{};
  std::size_t collected_ = 0;
  std::size_t index_ = state_size;
  bool ready_ = false;
};

} // namespace regadgets
