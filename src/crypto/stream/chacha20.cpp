#include "regadgets/crypto/stream/chacha20.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
bytes chacha20_crypt(std::span<const byte> key, std::span<const byte> nonce,
                     std::uint32_t counter, std::span<const byte> input,
                     std::size_t rounds) {
  if (key.size() != 32 || nonce.size() != 12 || rounds % 2 != 0)
    fail("chacha20 requires 32-byte key, 12-byte nonce, even rounds");
  auto qr = [](std::uint32_t &a, std::uint32_t &b, std::uint32_t &c,
               std::uint32_t &d) {
    a += b;
    d ^= a;
    d = std::rotl(d, 16);
    c += d;
    b ^= c;
    b = std::rotl(b, 12);
    a += b;
    d ^= a;
    d = std::rotl(d, 8);
    c += d;
    b ^= c;
    b = std::rotl(b, 7);
  };
  const std::array<std::uint32_t, 4> sigma{0x61707865, 0x3320646E, 0x79622D32,
                                           0x6B206574};
  bytes out(input.size());
  for (std::size_t off = 0; off < input.size(); off += 64) {
    std::array<std::uint32_t, 16> state{sigma[0],
                                        sigma[1],
                                        sigma[2],
                                        sigma[3],
                                        load_le32(key.subspan(0, 4)),
                                        load_le32(key.subspan(4, 4)),
                                        load_le32(key.subspan(8, 4)),
                                        load_le32(key.subspan(12, 4)),
                                        load_le32(key.subspan(16, 4)),
                                        load_le32(key.subspan(20, 4)),
                                        load_le32(key.subspan(24, 4)),
                                        load_le32(key.subspan(28, 4)),
                                        counter,
                                        load_le32(nonce.subspan(0, 4)),
                                        load_le32(nonce.subspan(4, 4)),
                                        load_le32(nonce.subspan(8, 4))};
    auto w = state;
    for (std::size_t i = 0; i < rounds; i += 2) {
      qr(w[0], w[4], w[8], w[12]);
      qr(w[1], w[5], w[9], w[13]);
      qr(w[2], w[6], w[10], w[14]);
      qr(w[3], w[7], w[11], w[15]);
      qr(w[0], w[5], w[10], w[15]);
      qr(w[1], w[6], w[11], w[12]);
      qr(w[2], w[7], w[8], w[13]);
      qr(w[3], w[4], w[9], w[14]);
    }
    std::array<byte, 64> block{};
    for (int i = 0; i < 16; ++i)
      store_le32(w[i] + state[i], block.data() + i * 4);
    auto chunk = std::min<std::size_t>(64, input.size() - off);
    for (std::size_t i = 0; i < chunk; ++i)
      out[off + i] = input[off + i] ^ block[i];
    ++counter;
  }
  return out;
}

} // namespace regadgets
