#include "regadgets/crypto/block/xxtea.hpp"
#include "common.hpp"

namespace regadgets {
static std::vector<std::uint32_t> xxtea_words(std::span<const byte> input,
                                              bool include_size) {
  std::vector<std::uint32_t> out((input.size() + 3) / 4, 0);
  for (std::size_t i = 0; i < input.size(); ++i)
    out[i / 4] |= static_cast<std::uint32_t>(input[i]) << ((i % 4) * 8U);
  if (include_size)
    out.push_back(static_cast<std::uint32_t>(input.size()));
  return out;
}
static bytes xxtea_bytes(const std::vector<std::uint32_t> &words,
                         bool include_size) {
  std::size_t size = words.size() * 4, count = words.size();
  if (include_size && !words.empty()) {
    size = words.back();
    count -= 1;
  }
  bytes out(count * 4);
  for (std::size_t i = 0; i < count; ++i)
    store_le32(words[i], out.data() + i * 4);
  out.resize(size);
  return out;
}
bytes xxtea_encrypt(std::span<const byte> input,
                    std::array<std::uint32_t, 4> key, xxtea_options options) {
  auto v = xxtea_words(input, true);
  if (v.size() < 2)
    return bytes(input.begin(), input.end());
  constexpr std::uint32_t delta = 0x9E3779B9u;
  std::size_t n = v.size();
  std::uint32_t rounds = 6U + 52U / static_cast<std::uint32_t>(n) +
                         options.rounds_bias,
                sum = 0, z = v[n - 1];
  for (std::uint32_t q = 0; q < rounds; ++q) {
    sum += delta;
    std::uint32_t e = (sum >> options.shift) & 3U;
    for (std::size_t p = 0; p < n - 1; ++p) {
      std::uint32_t y = v[p + 1];
      std::uint32_t mx = (((z >> 5U) ^ (y << 2U)) + ((y >> 3U) ^ (z << 4U))) ^
                         ((sum ^ y) + (key[(p & 3U) ^ e] ^ z));
      z = v[p] += mx;
    }
    std::uint32_t y = v[0];
    std::uint32_t mx = (((z >> 5U) ^ (y << 2U)) + ((y >> 3U) ^ (z << 4U))) ^
                       ((sum ^ y) + (key[((n - 1) & 3U) ^ e] ^ z));
    z = v[n - 1] += mx;
  }
  return xxtea_bytes(v, false);
}
bytes xxtea_decrypt(std::span<const byte> input,
                    std::array<std::uint32_t, 4> key, xxtea_options options) {
  auto v = xxtea_words(input, false);
  if (v.size() < 2)
    return bytes(input.begin(), input.end());
  constexpr std::uint32_t delta = 0x9E3779B9u;
  std::size_t n = v.size();
  std::uint32_t rounds = 6U + 52U / static_cast<std::uint32_t>(n) +
                         options.rounds_bias,
                sum = rounds * delta, y = v[0];
  while (sum != 0) {
    std::uint32_t e = (sum >> options.shift) & 3U;
    for (std::size_t p = n - 1; p > 0; --p) {
      std::uint32_t z = v[p - 1];
      std::uint32_t mx = (((z >> 5U) ^ (y << 2U)) + ((y >> 3U) ^ (z << 4U))) ^
                         ((sum ^ y) + (key[(p & 3U) ^ e] ^ z));
      y = v[p] -= mx;
    }
    std::uint32_t z = v[n - 1];
    std::uint32_t mx = (((z >> 5U) ^ (y << 2U)) + ((y >> 3U) ^ (z << 4U))) ^
                       ((sum ^ y) + (key[e] ^ z));
    y = v[0] -= mx;
    sum -= delta;
  }
  return xxtea_bytes(v, true);
}

} // namespace regadgets
