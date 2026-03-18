#include "regadgets/crypto/block/rc5.hpp"
#include "common.hpp"

namespace regadgets {
static std::vector<std::uint32_t> rc5_expand(std::span<const byte> key,
                                             std::uint32_t rounds) {
  const std::uint32_t pw = 0xB7E15163u, qw = 0x9E3779B9u;
  std::vector<std::uint32_t> L((key.size() + 3) / 4, 0);
  for (std::size_t i = 0; i < key.size(); ++i)
    L[i / 4] |= static_cast<std::uint32_t>(key[i]) << ((i % 4) * 8U);
  std::vector<std::uint32_t> S(2 * (rounds + 1));
  S[0] = pw;
  for (std::size_t i = 1; i < S.size(); ++i)
    S[i] = S[i - 1] + qw;
  std::uint32_t a = 0, b = 0;
  std::size_t i = 0, j = 0, loops = 3 * std::max(S.size(), L.size());
  if (L.empty())
    L.push_back(0);
  for (std::size_t k = 0; k < loops; ++k) {
    a = S[i] = rol<std::uint32_t>(S[i] + a + b, 3);
    b = L[j] = rol<std::uint32_t>(L[j] + a + b, (a + b) & 31U);
    i = (i + 1) % S.size();
    j = (j + 1) % L.size();
  }
  return S;
}
bytes rc5_encrypt(std::span<const byte> input, std::span<const byte> key,
                  std::uint32_t word_bits, std::uint32_t rounds) {
  if (word_bits != 32)
    fail("this build implements RC5-32 only");
  bytes data = pkcs7_pad(input, 8);
  const auto S = rc5_expand(key, rounds);
  for (std::size_t i = 0; i < data.size(); i += 8) {
    std::uint32_t a = load_le32({data.data() + i, 4}),
                  b = load_le32({data.data() + i + 4, 4});
    a += S[0];
    b += S[1];
    for (std::uint32_t r = 1; r <= rounds; ++r) {
      a = rol<std::uint32_t>(a ^ b, b & 31U) + S[2 * r];
      b = rol<std::uint32_t>(b ^ a, a & 31U) + S[2 * r + 1];
    }
    store_le32(a, data.data() + i);
    store_le32(b, data.data() + i + 4);
  }
  return data;
}
bytes rc5_decrypt(std::span<const byte> input, std::span<const byte> key,
                  std::uint32_t word_bits, std::uint32_t rounds) {
  if (word_bits != 32)
    fail("this build implements RC5-32 only");
  bytes data(input.begin(), input.end());
  if (data.size() % 8 != 0)
    fail("invalid RC5 block size");
  const auto S = rc5_expand(key, rounds);
  for (std::size_t i = 0; i < data.size(); i += 8) {
    std::uint32_t a = load_le32({data.data() + i, 4}),
                  b = load_le32({data.data() + i + 4, 4});
    for (std::uint32_t r = rounds; r >= 1; --r) {
      b = ror<std::uint32_t>(b - S[2 * r + 1], a & 31U) ^ a;
      a = ror<std::uint32_t>(a - S[2 * r], b & 31U) ^ b;
      if (r == 1)
        break;
    }
    b -= S[1];
    a -= S[0];
    store_le32(a, data.data() + i);
    store_le32(b, data.data() + i + 4);
  }
  return pkcs7_unpad(data, 8);
}

} // namespace regadgets
