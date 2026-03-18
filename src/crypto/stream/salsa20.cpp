#include "regadgets/crypto/stream/salsa20.hpp"

#include "src/crypto/block/common.hpp"

namespace regadgets {

bytes salsa20_crypt(std::span<const byte> key, std::span<const byte> nonce,
                    std::uint64_t counter, std::span<const byte> input,
                    std::size_t rounds) {
  if (key.size() != 32 || nonce.size() != 8 || rounds % 2 != 0) {
    fail("salsa20 requires 32-byte key, 8-byte nonce, even rounds");
  }

  auto qr = [](std::uint32_t &y0, std::uint32_t &y1, std::uint32_t &y2,
               std::uint32_t &y3) {
    y1 ^= std::rotl(y0 + y3, 7);
    y2 ^= std::rotl(y1 + y0, 9);
    y3 ^= std::rotl(y2 + y1, 13);
    y0 ^= std::rotl(y3 + y2, 18);
  };

  const std::array<std::uint32_t, 4> sigma{0x61707865, 0x3320646E, 0x79622D32,
                                           0x6B206574};

  bytes out(input.size());
  for (std::size_t off = 0; off < input.size(); off += 64) {
    std::array<std::uint32_t, 16> state{
        sigma[0],
        load_le32(key.subspan(0, 4)),
        load_le32(key.subspan(4, 4)),
        load_le32(key.subspan(8, 4)),
        load_le32(key.subspan(12, 4)),
        sigma[1],
        load_le32(nonce.subspan(0, 4)),
        load_le32(nonce.subspan(4, 4)),
        static_cast<std::uint32_t>(counter),
        static_cast<std::uint32_t>(counter >> 32U),
        sigma[2],
        load_le32(key.subspan(16, 4)),
        load_le32(key.subspan(20, 4)),
        load_le32(key.subspan(24, 4)),
        load_le32(key.subspan(28, 4)),
        sigma[3],
    };

    auto w = state;
    for (std::size_t i = 0; i < rounds; i += 2) {
      qr(w[0], w[4], w[8], w[12]);
      qr(w[5], w[9], w[13], w[1]);
      qr(w[10], w[14], w[2], w[6]);
      qr(w[15], w[3], w[7], w[11]);
      qr(w[0], w[1], w[2], w[3]);
      qr(w[5], w[6], w[7], w[4]);
      qr(w[10], w[11], w[8], w[9]);
      qr(w[15], w[12], w[13], w[14]);
    }

    std::array<byte, 64> block{};
    for (int i = 0; i < 16; ++i) {
      store_le32(w[i] + state[i], block.data() + i * 4);
    }

    const auto chunk = std::min<std::size_t>(64, input.size() - off);
    for (std::size_t i = 0; i < chunk; ++i) {
      out[off + i] = input[off + i] ^ block[i];
    }

    ++counter;
  }

  return out;
}

} // namespace regadgets
