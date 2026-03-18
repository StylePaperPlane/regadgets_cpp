#include "regadgets/encoding/base2048.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
#ifdef REGADGETS_ENABLE_BASE2048
std::u32string encode_b2048(std::span<const byte> input,
                            std::span<const char32_t> alphabet) {
  if (alphabet.size() != 2048)
    fail("base2048 alphabet must have 2048 code points");
  std::u32string out;
  std::uint32_t buf = 0;
  int bits = 0;
  for (byte b : input) {
    buf = (buf << 8U) | b;
    bits += 8;
    while (bits >= 11) {
      bits -= 11;
      out.push_back(alphabet[(buf >> bits) & 0x7FFU]);
    }
  }
  if (bits > 0)
    out.push_back(alphabet[(buf << (11 - bits)) & 0x7FFU]);
  return out;
}
bytes decode_b2048(std::u32string_view input,
                   std::span<const char32_t> alphabet) {
  if (alphabet.size() != 2048)
    fail("base2048 alphabet must have 2048 code points");
  std::vector<int> rev(4096, -1);
  for (std::size_t i = 0; i < alphabet.size(); ++i)
    rev[alphabet[i]] = static_cast<int>(i);
  bytes out;
  std::uint32_t buf = 0;
  int bits = 0;
  for (char32_t ch : input) {
    if (ch >= static_cast<char32_t>(rev.size()) || rev[ch] < 0)
      fail("invalid base2048 character");
    buf = (buf << 11U) | static_cast<std::uint32_t>(rev[ch]);
    bits += 11;
    while (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<byte>((buf >> bits) & 0xFFU));
    }
  }
  return out;
}
#endif

} // namespace regadgets
