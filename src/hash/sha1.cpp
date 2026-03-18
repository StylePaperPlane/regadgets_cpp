#include "regadgets/hash/sha1.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
bytes sha1(std::span<const byte> input) {
  bytes data(input.begin(), input.end());
  std::uint64_t bits = data.size() * 8ULL;
  data.push_back(0x80);
  while ((data.size() % 64) != 56)
    data.push_back(0);
  bytes len = qword_to_bytes(bits, false);
  data.insert(data.end(), len.begin(), len.end());
  std::array<std::uint32_t, 5> h{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                                 0xC3D2E1F0};
  for (std::size_t off = 0; off < data.size(); off += 64) {
    std::array<std::uint32_t, 80> w{};
    for (int i = 0; i < 16; ++i)
      w[i] = load_be32({data.data() + off + i * 4, 4});
    for (int i = 16; i < 80; ++i)
      w[i] = std::rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    auto [a, b, c, d, e] = h;
    for (int i = 0; i < 80; ++i) {
      std::uint32_t f = 0, k = 0;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      auto temp = std::rotl(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = std::rotl(b, 30);
      b = a;
      a = temp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }
  bytes out(20);
  for (int i = 0; i < 5; ++i)
    store_be32(h[i], out.data() + i * 4);
  return out;
}

} // namespace regadgets
