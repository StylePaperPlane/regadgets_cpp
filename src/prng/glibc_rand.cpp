#include "regadgets/prng/glibc_rand.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
GLIBCRand::GLIBCRand(std::uint32_t seed_value) { seed(seed_value); }
void GLIBCRand::seed(std::uint32_t value) {
  state_[0] = value;
  for (std::size_t i = 1; i < 31; ++i)
    state_[i] =
        static_cast<std::uint32_t>((16807ull * state_[i - 1]) % 2147483647ull);
  for (std::size_t i = 31; i < 34; ++i)
    state_[i] = state_[i - 31];
  for (std::size_t i = 34; i < state_.size(); ++i)
    state_[i] = state_[i - 31] + state_[i - 3];
  index_ = 344;
}
std::uint32_t GLIBCRand::next() {
  state_[index_ % state_.size()] = state_[(index_ - 31) % state_.size()] +
                                   state_[(index_ - 3) % state_.size()];
  std::uint32_t value = state_[index_ % state_.size()] >> 1U;
  ++index_;
  return value;
}
std::vector<std::uint32_t> GLIBCRand::sequence(std::size_t count) {
  std::vector<std::uint32_t> out(count);
  for (auto &v : out)
    v = next();
  return out;
}

} // namespace regadgets
