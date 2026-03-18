#include "regadgets/crypto/block/xtea.hpp"

#include "common.hpp"

namespace regadgets {

std::array<std::uint32_t, 2> xtea_encrypt(std::array<std::uint32_t, 2> block,
                                          std::array<std::uint32_t, 4> key,
                                          std::uint32_t rounds) {
  std::uint32_t v0 = block[0], v1 = block[1], sum = 0;
  constexpr std::uint32_t delta = 0x9E3779B9u;
  for (std::uint32_t i = 0; i < rounds; ++i) {
    v0 += (((v1 << 4U) ^ (v1 >> 5U)) + v1) ^ (sum + key[sum & 3U]);
    sum += delta;
    v1 += (((v0 << 4U) ^ (v0 >> 5U)) + v0) ^ (sum + key[(sum >> 11U) & 3U]);
  }
  return {v0, v1};
}

std::array<std::uint32_t, 2> xtea_decrypt(std::array<std::uint32_t, 2> block,
                                          std::array<std::uint32_t, 4> key,
                                          std::uint32_t rounds) {
  std::uint32_t v0 = block[0], v1 = block[1], sum = 0x9E3779B9u * rounds;
  constexpr std::uint32_t delta = 0x9E3779B9u;
  for (std::uint32_t i = 0; i < rounds; ++i) {
    v1 -= (((v0 << 4U) ^ (v0 >> 5U)) + v0) ^ (sum + key[(sum >> 11U) & 3U]);
    sum -= delta;
    v0 -= (((v1 << 4U) ^ (v1 >> 5U)) + v1) ^ (sum + key[sum & 3U]);
  }
  return {v0, v1};
}

bytes xtea_encrypt(std::span<const byte> input,
                   std::array<std::uint32_t, 4> key, std::uint32_t rounds) {
  bytes data = pkcs7_pad(input, 8);
  bytes out(data.size());
  for (std::size_t offset = 0; offset < data.size(); offset += 8) {
    const std::array<std::uint32_t, 2> block{
        load_le32(std::span<const byte>(data.data() + offset, 4)),
        load_le32(std::span<const byte>(data.data() + offset + 4, 4)),
    };
    const auto encrypted = xtea_encrypt(block, key, rounds);
    store_le32(encrypted[0], out.data() + offset);
    store_le32(encrypted[1], out.data() + offset + 4);
  }
  return out;
}

bytes xtea_decrypt(std::span<const byte> input,
                   std::array<std::uint32_t, 4> key, std::uint32_t rounds) {
  if (input.size() % 8 != 0) {
    fail("XTEA input size must be a multiple of 8 bytes");
  }

  bytes out(input.size());
  for (std::size_t offset = 0; offset < input.size(); offset += 8) {
    const std::array<std::uint32_t, 2> block{
        load_le32(input.subspan(offset, 4)),
        load_le32(input.subspan(offset + 4, 4)),
    };
    const auto decrypted = xtea_decrypt(block, key, rounds);
    store_le32(decrypted[0], out.data() + offset);
    store_le32(decrypted[1], out.data() + offset + 4);
  }
  return pkcs7_unpad(out, 8);
}

} // namespace regadgets
