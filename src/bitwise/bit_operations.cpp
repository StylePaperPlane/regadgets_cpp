#include "regadgets/bitwise/bit_operations.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
bytes bxor(std::span<const byte> lhs, std::span<const byte> rhs) {
  if (lhs.size() != rhs.size())
    fail("xor inputs must have same size");
  bytes out(lhs.size());
  for (std::size_t i = 0; i < lhs.size(); ++i)
    out[i] = lhs[i] ^ rhs[i];
  return out;
}
bytes bxor_cycle(std::span<const byte> lhs, std::span<const byte> rhs) {
  if (rhs.empty())
    fail("cycle xor key must not be empty");
  bytes out(lhs.size());
  for (std::size_t i = 0; i < lhs.size(); ++i)
    out[i] = lhs[i] ^ rhs[i % rhs.size()];
  return out;
}
bytes bxorr_enc(std::span<const byte> input, byte seed) {
  bytes out(input.begin(), input.end());
  byte prev = seed;
  for (auto &b : out) {
    b ^= prev;
    prev = b;
  }
  return out;
}
bytes bxorr_dec(std::span<const byte> input, byte seed) {
  bytes out(input.begin(), input.end());
  byte prev = seed;
  for (auto &b : out) {
    byte cur = b;
    b ^= prev;
    prev = cur;
  }
  return out;
}
bytes bxorl_enc(std::span<const byte> input, byte seed) {
  bytes out(input.begin(), input.end());
  byte prev = seed;
  for (std::size_t i = out.size(); i-- > 0;) {
    out[i] ^= prev;
    prev = out[i];
  }
  return out;
}
bytes bxorl_dec(std::span<const byte> input, byte seed) {
  bytes out(input.begin(), input.end());
  byte prev = seed;
  for (std::size_t i = out.size(); i-- > 0;) {
    byte cur = out[i];
    out[i] ^= prev;
    prev = cur;
  }
  return out;
}

} // namespace regadgets
