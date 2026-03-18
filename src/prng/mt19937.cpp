#include "regadgets/prng/mt19937.hpp"

#include <stdexcept>

namespace regadgets {
namespace {

constexpr std::size_t kStateSize = MT19937::state_size;
constexpr std::size_t kMiddleWord = 397;
constexpr std::uint32_t kMatrixA = 0x9908b0dfu;
constexpr std::uint32_t kUpperMask = 0x80000000u;
constexpr std::uint32_t kLowerMask = 0x7fffffffu;

std::uint32_t temper(std::uint32_t value) {
  value ^= value >> 11U;
  value ^= (value << 7U) & 0x9d2c5680u;
  value ^= (value << 15U) & 0xefc60000u;
  value ^= value >> 18U;
  return value;
}

std::uint32_t undo_right_shift_xor(std::uint32_t value, unsigned int shift) {
  std::uint32_t result = 0;
  for (int bit = 31; bit >= 0; --bit) {
    const std::uint32_t shifted =
        (bit + static_cast<int>(shift) <= 31)
            ? ((result >> (bit + static_cast<int>(shift))) & 1u)
            : 0u;
    const std::uint32_t current = ((value >> bit) & 1u) ^ shifted;
    result |= current << bit;
  }
  return result;
}

std::uint32_t undo_left_shift_xor_mask(std::uint32_t value, unsigned int shift,
                                       std::uint32_t mask) {
  std::uint32_t result = 0;
  for (unsigned int bit = 0; bit < 32; ++bit) {
    const std::uint32_t shifted =
        (bit >= shift && ((mask >> bit) & 1u) != 0u)
            ? ((result >> (bit - shift)) & 1u)
            : 0u;
    const std::uint32_t current = ((value >> bit) & 1u) ^ shifted;
    result |= current << bit;
  }
  return result;
}

std::uint32_t untemper(std::uint32_t value) {
  value = undo_right_shift_xor(value, 18);
  value = undo_left_shift_xor_mask(value, 15, 0xefc60000u);
  value = undo_left_shift_xor_mask(value, 7, 0x9d2c5680u);
  value = undo_right_shift_xor(value, 11);
  return value;
}

void twist(std::array<std::uint32_t, kStateSize> &state) {
  for (std::size_t i = 0; i < kStateSize; ++i) {
    const std::uint32_t mixed =
        (state[i] & kUpperMask) | (state[(i + 1) % kStateSize] & kLowerMask);
    state[i] = state[(i + kMiddleWord) % kStateSize] ^ (mixed >> 1U);
    if ((mixed & 1u) != 0u) {
      state[i] ^= kMatrixA;
    }
  }
}

} // namespace

MT19937::MT19937(std::uint32_t seed_value) { seed(seed_value); }

void MT19937::seed(std::uint32_t value) {
  state_[0] = value;
  for (std::size_t i = 1; i < state_.size(); ++i) {
    state_[i] = 1812433253u * (state_[i - 1] ^ (state_[i - 1] >> 30U)) +
                static_cast<std::uint32_t>(i);
  }
  index_ = state_.size();
}

std::uint32_t MT19937::next() {
  if (index_ >= state_.size()) {
    twist(state_);
    index_ = 0;
  }
  return temper(state_[index_++]);
}

std::vector<std::uint32_t> MT19937::sequence(std::size_t count) {
  std::vector<std::uint32_t> out(count);
  for (auto &value : out) {
    value = next();
  }
  return out;
}

void MT19937Predictor::reset() {
  state_.fill(0);
  collected_ = 0;
  index_ = state_.size();
  ready_ = false;
}

void MT19937Predictor::submit(std::uint32_t sample) {
  if (ready_) {
    throw std::invalid_argument(
        "MT19937 predictor already recovered 624 samples");
  }
  state_[collected_++] = untemper(sample);
  if (collected_ == state_.size()) {
    ready_ = true;
    index_ = state_.size();
  }
}

void MT19937Predictor::submit(std::span<const std::uint32_t> samples) {
  if (collected_ + samples.size() > state_.size()) {
    throw std::invalid_argument(
        "MT19937 predictor accepts at most 624 samples");
  }
  for (std::uint32_t sample : samples) {
    submit(sample);
  }
}

bool MT19937Predictor::ready() const noexcept { return ready_; }

std::size_t MT19937Predictor::samples_collected() const noexcept {
  return collected_;
}

std::uint32_t MT19937Predictor::next() {
  if (!ready_) {
    throw std::invalid_argument(
        "MT19937 predictor needs 624 samples before prediction");
  }
  if (index_ >= state_.size()) {
    twist(state_);
    index_ = 0;
  }
  return temper(state_[index_++]);
}

std::vector<std::uint32_t> MT19937Predictor::sequence(std::size_t count) {
  std::vector<std::uint32_t> out(count);
  for (auto &value : out) {
    value = next();
  }
  return out;
}

} // namespace regadgets
