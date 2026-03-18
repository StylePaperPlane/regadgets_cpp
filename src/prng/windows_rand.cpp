#include "regadgets/prng/windows_rand.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
WindowsRand::WindowsRand(std::uint32_t seed_value) : state_(seed_value) {}
void WindowsRand::seed(std::uint32_t value) { state_ = value; }
std::uint32_t WindowsRand::next() {
  state_ = state_ * 214013u + 2531011u;
  return (state_ >> 16U) & 0x7FFFu;
}
std::vector<std::uint32_t> WindowsRand::sequence(std::size_t count) {
  std::vector<std::uint32_t> out(count);
  for (auto &v : out)
    v = next();
  return out;
}

} // namespace regadgets
