#include "regadgets/hash/md5.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
bytes md5(std::span<const byte> input) {
  static constexpr std::array<std::uint32_t, 64> s = {
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
  static const std::array<std::uint32_t, 64> k = []() {
    std::array<std::uint32_t, 64> out{};
    for (std::size_t i = 0; i < out.size(); ++i)
      out[i] = static_cast<std::uint32_t>(std::floor(
          std::abs(std::sin(static_cast<double>(i + 1))) * 4294967296.0));
    return out;
  }();
  bytes data(input.begin(), input.end());
  std::uint64_t bits = data.size() * 8ULL;
  data.push_back(0x80);
  while ((data.size() % 64) != 56)
    data.push_back(0);
  for (int i = 0; i < 8; ++i)
    data.push_back(static_cast<byte>(bits >> (8U * i)));
  std::uint32_t a0 = 0x67452301, b0 = 0xEFCDAB89, c0 = 0x98BADCFE,
                d0 = 0x10325476;
  for (std::size_t off = 0; off < data.size(); off += 64) {
    std::uint32_t M[16];
    for (int i = 0; i < 16; ++i)
      M[i] = load_le32({data.data() + off + i * 4, 4});
    std::uint32_t A = a0, B = b0, C = c0, D = d0;
    for (int i = 0; i < 64; ++i) {
      std::uint32_t F = 0, g = 0;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) & 15;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) & 15;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) & 15;
      }
      F += A + k[i] + M[g];
      A = D;
      D = C;
      C = B;
      B += std::rotl(F, static_cast<int>(s[i]));
    }
    a0 += A;
    b0 += B;
    c0 += C;
    d0 += D;
  }
  bytes out(16);
  store_le32(a0, out.data());
  store_le32(b0, out.data() + 4);
  store_le32(c0, out.data() + 8);
  store_le32(d0, out.data() + 12);
  return out;
}

} // namespace regadgets
