#include "regadgets/hash/sha256.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
bytes sha256(std::span<const byte> input) {
  static constexpr std::array<std::uint32_t, 64> k = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
      0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
      0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
      0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
      0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
      0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
      0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
      0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
      0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};
  bytes data(input.begin(), input.end());
  std::uint64_t bits = data.size() * 8ULL;
  data.push_back(0x80);
  while ((data.size() % 64) != 56)
    data.push_back(0);
  bytes len = qword_to_bytes(bits, false);
  data.insert(data.end(), len.begin(), len.end());
  std::array<std::uint32_t, 8> h{0x6A09E667, 0xBB67AE85, 0x3C6EF372,
                                 0xA54FF53A, 0x510E527F, 0x9B05688C,
                                 0x1F83D9AB, 0x5BE0CD19};
  for (std::size_t off = 0; off < data.size(); off += 64) {
    std::array<std::uint32_t, 64> w{};
    for (int i = 0; i < 16; ++i)
      w[i] = load_be32({data.data() + off + i * 4, 4});
    for (int i = 16; i < 64; ++i) {
      auto s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^
                (w[i - 15] >> 3U);
      auto s1 =
          std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto [a, b, c, d, e, f, g, hv] = h;
    for (int i = 0; i < 64; ++i) {
      auto S1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      auto ch = (e & f) ^ (~e & g);
      auto temp1 = hv + S1 + ch + k[i] + w[i];
      auto S0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      auto maj = (a & b) ^ (a & c) ^ (b & c);
      auto temp2 = S0 + maj;
      hv = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hv;
  }
  bytes out(32);
  for (int i = 0; i < 8; ++i)
    store_be32(h[i], out.data() + i * 4);
  return out;
}

} // namespace regadgets
