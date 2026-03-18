#include "regadgets/reverse/sbox.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
std::pair<bytes, bytes> generate_sbox(std::span<const byte> permutation) {
  bytes sbox(256), inv(256);
  if (permutation.empty())
    std::iota(sbox.begin(), sbox.end(), 0);
  else {
    if (permutation.size() != 256)
      fail("sbox permutation must contain 256 bytes");
    sbox.assign(permutation.begin(), permutation.end());
  }
  for (std::size_t i = 0; i < sbox.size(); ++i)
    inv[sbox[i]] = static_cast<byte>(i);
  return {sbox, inv};
}
bytes sbox_transform(std::span<const byte> input, std::span<const byte> sbox) {
  if (sbox.size() != 256)
    fail("sbox must have 256 entries");
  bytes out(input.size());
  for (std::size_t i = 0; i < input.size(); ++i)
    out[i] = sbox[input[i]];
  return out;
}

} // namespace regadgets
