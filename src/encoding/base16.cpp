#include "regadgets/encoding/base16.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
std::string encode_b16(std::span<const byte> input, std::string_view alphabet) {
  if (alphabet.size() != 16)
    fail("base16 alphabet must have 16 chars");
  std::string out;
  out.reserve(input.size() * 2);
  for (byte b : input) {
    out.push_back(alphabet[b >> 4U]);
    out.push_back(alphabet[b & 0x0FU]);
  }
  return out;
}
bytes decode_b16(std::string_view input, std::string_view alphabet) {
  if (alphabet.size() != 16 || input.size() % 2 != 0)
    fail("invalid base16 input");
  const auto rev = inverse_table(alphabet);
  bytes out(input.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    int hi = rev[static_cast<byte>(input[i * 2])],
        lo = rev[static_cast<byte>(input[i * 2 + 1])];
    if (hi < 0 || lo < 0)
      fail("invalid base16 character");
    out[i] = static_cast<byte>((hi << 4) | lo);
  }
  return out;
}

} // namespace regadgets
