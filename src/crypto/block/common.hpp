#pragma once

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include "regadgets/regadgets.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <functional>
#include <numeric>
#include <stdexcept>

namespace regadgets {
namespace {
constexpr double kPi = 3.14159265358979323846;
[[noreturn]] void fail(const std::string &message) {
  throw std::runtime_error(message);
}
std::uint32_t load_le32(std::span<const byte> s) {
  return static_cast<std::uint32_t>(s[0]) |
         (static_cast<std::uint32_t>(s[1]) << 8U) |
         (static_cast<std::uint32_t>(s[2]) << 16U) |
         (static_cast<std::uint32_t>(s[3]) << 24U);
}
std::uint32_t load_be32(std::span<const byte> s) {
  return (static_cast<std::uint32_t>(s[0]) << 24U) |
         (static_cast<std::uint32_t>(s[1]) << 16U) |
         (static_cast<std::uint32_t>(s[2]) << 8U) |
         static_cast<std::uint32_t>(s[3]);
}
std::uint64_t load_be64(std::span<const byte> s) {
  std::uint64_t v = 0;
  for (byte b : s)
    v = (v << 8U) | b;
  return v;
}
void store_le32(std::uint32_t v, byte *out) {
  out[0] = static_cast<byte>(v);
  out[1] = static_cast<byte>(v >> 8U);
  out[2] = static_cast<byte>(v >> 16U);
  out[3] = static_cast<byte>(v >> 24U);
}
void store_be32(std::uint32_t v, byte *out) {
  out[0] = static_cast<byte>(v >> 24U);
  out[1] = static_cast<byte>(v >> 16U);
  out[2] = static_cast<byte>(v >> 8U);
  out[3] = static_cast<byte>(v);
}
void store_be64(std::uint64_t v, byte *out) {
  for (int i = 7; i >= 0; --i) {
    out[i] = static_cast<byte>(v);
    v >>= 8U;
  }
}
std::vector<int> inverse_table(std::string_view alphabet) {
  std::vector<int> t(256, -1);
  for (std::size_t i = 0; i < alphabet.size(); ++i)
    t[static_cast<byte>(alphabet[i])] = static_cast<int>(i);
  return t;
}
bytes pkcs7_pad(std::span<const byte> input, std::size_t block) {
  bytes out(input.begin(), input.end());
  byte pad = static_cast<byte>(block - (out.size() % block));
  if (pad == 0)
    pad = static_cast<byte>(block);
  out.insert(out.end(), pad, pad);
  return out;
}
bytes pkcs7_unpad(std::span<const byte> input, std::size_t block) {
  if (input.empty() || input.size() % block != 0)
    fail("invalid padding size");
  byte pad = input.back();
  if (pad == 0 || pad > block || pad > input.size())
    fail("invalid padding");
  for (std::size_t i = input.size() - pad; i < input.size(); ++i)
    if (input[i] != pad)
      fail("invalid padding bytes");
  return bytes(input.begin(), input.end() - pad);
}
std::string encode_radix(std::span<const byte> input,
                         std::string_view alphabet) {
  if (alphabet.empty())
    return {};
  std::vector<int> digits(1, 0);
  for (byte b : input) {
    int carry = b;
    for (auto &d : digits) {
      carry += d * 256;
      d = carry % static_cast<int>(alphabet.size());
      carry /= static_cast<int>(alphabet.size());
    }
    while (carry > 0) {
      digits.push_back(carry % static_cast<int>(alphabet.size()));
      carry /= static_cast<int>(alphabet.size());
    }
  }
  std::string out;
  for (byte b : input) {
    if (b == 0)
      out.push_back(alphabet.front());
    else
      break;
  }
  for (auto it = digits.rbegin(); it != digits.rend(); ++it)
    out.push_back(alphabet[static_cast<std::size_t>(*it)]);
  return out;
}
bytes decode_radix(std::string_view input, std::string_view alphabet) {
  if (alphabet.empty())
    return {};
  const auto rev = inverse_table(alphabet);
  std::vector<int> digits(1, 0);
  for (char ch : input) {
    int value = rev[static_cast<byte>(ch)];
    if (value < 0)
      fail("invalid encoded character");
    int carry = value;
    for (auto &d : digits) {
      carry += d * static_cast<int>(alphabet.size());
      d = carry & 0xFF;
      carry >>= 8;
    }
    while (carry > 0) {
      digits.push_back(carry & 0xFF);
      carry >>= 8;
    }
  }
  bytes out;
  for (char ch : input) {
    if (ch == alphabet.front())
      out.push_back(0);
    else
      break;
  }
  for (auto it = digits.rbegin(); it != digits.rend(); ++it)
    out.push_back(static_cast<byte>(*it));
  return out;
}
std::string encode_pow2(std::span<const byte> input, std::string_view alphabet,
                        int bits, bool pad) {
  std::string out;
  std::uint32_t buf = 0;
  int count = 0;
  const std::uint32_t mask = (1U << bits) - 1U;
  for (byte b : input) {
    buf = (buf << 8U) | b;
    count += 8;
    while (count >= bits) {
      count -= bits;
      out.push_back(alphabet[(buf >> count) & mask]);
    }
  }
  if (count > 0)
    out.push_back(alphabet[(buf << (bits - count)) & mask]);
  if (pad) {
    std::size_t group = bits == 5 ? 8 : 4;
    while (out.size() % group != 0)
      out.push_back('=');
  }
  return out;
}
bytes decode_pow2(std::string_view input, std::string_view alphabet, int bits) {
  const auto rev = inverse_table(alphabet);
  bytes out;
  std::uint32_t buf = 0;
  int count = 0;
  for (char ch : input) {
    if (ch == '=')
      break;
    int value = rev[static_cast<byte>(ch)];
    if (value < 0)
      fail("invalid encoded character");
    buf = (buf << bits) | static_cast<std::uint32_t>(value);
    count += bits;
    while (count >= 8) {
      count -= 8;
      out.push_back(static_cast<byte>((buf >> count) & 0xFFU));
    }
  }
  return out;
}
std::array<byte, 256> aes_sbox() {
  std::array<byte, 256> box{};
  auto mul = [](byte a, byte b) {
    byte r = 0;
    for (int i = 0; i < 8; ++i) {
      if (b & 1U)
        r ^= a;
      bool hi = (a & 0x80U) != 0;
      a <<= 1U;
      if (hi)
        a ^= 0x1BU;
      b >>= 1U;
    }
    return r;
  };
  auto pow = [&](byte a, int n) {
    byte r = 1;
    while (n > 0) {
      if (n & 1)
        r = mul(r, a);
      a = mul(a, a);
      n >>= 1;
    }
    return r;
  };
  for (int i = 0; i < 256; ++i) {
    byte x = i == 0 ? 0 : pow(static_cast<byte>(i), 254);
    box[i] = static_cast<byte>(0x63U ^ x ^ rol<byte>(x, 1) ^ rol<byte>(x, 2) ^
                               rol<byte>(x, 3) ^ rol<byte>(x, 4));
  }
  return box;
}
std::array<byte, 256> aes_inv_sbox(const std::array<byte, 256> &box) {
  std::array<byte, 256> inv{};
  for (std::size_t i = 0; i < box.size(); ++i)
    inv[box[i]] = static_cast<byte>(i);
  return inv;
}
byte aes_mul(byte a, byte b) {
  byte r = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1U)
      r ^= a;
    bool hi = (a & 0x80U) != 0;
    a <<= 1U;
    if (hi)
      a ^= 0x1BU;
    b >>= 1U;
  }
  return r;
}
struct aes_ctx {
  int nr = 10;
  std::vector<std::array<byte, 16>> round_keys;
};
aes_ctx aes_expand_key(std::span<const byte> key, const aes_params &params) {
  const std::size_t nk = key.size() / 4;
  const int nr = params.rounds == 0 ? (nk == 8 ? 14 : 10)
                                    : static_cast<int>(params.rounds);
  if (params.rcon.size() <= static_cast<std::size_t>(nr / 2))
    fail("AES parameters require enough round constants");
  std::vector<std::uint32_t> words(4 * (nr + 1));
  for (std::size_t i = 0; i < nk; ++i)
    words[i] = load_be32(key.subspan(i * 4, 4));
  for (std::size_t i = nk; i < words.size(); ++i) {
    std::uint32_t temp = words[i - 1];
    if (i % nk == 0) {
      temp = std::rotl(temp, 8);
      temp = (static_cast<std::uint32_t>(params.sbox[(temp >> 24U) & 0xFFU]) << 24U) |
             (static_cast<std::uint32_t>(params.sbox[(temp >> 16U) & 0xFFU]) << 16U) |
             (static_cast<std::uint32_t>(params.sbox[(temp >> 8U) & 0xFFU]) << 8U) |
             params.sbox[temp & 0xFFU];
      temp ^= static_cast<std::uint32_t>(params.rcon[i / nk]) << 24U;
    } else if (nk > 6 && i % nk == 4) {
      temp = (static_cast<std::uint32_t>(params.sbox[(temp >> 24U) & 0xFFU]) << 24U) |
             (static_cast<std::uint32_t>(params.sbox[(temp >> 16U) & 0xFFU]) << 16U) |
             (static_cast<std::uint32_t>(params.sbox[(temp >> 8U) & 0xFFU]) << 8U) |
             params.sbox[temp & 0xFFU];
    }
    words[i] = words[i - nk] ^ temp;
  }
  aes_ctx ctx;
  ctx.nr = nr;
  ctx.round_keys.resize(nr + 1);
  for (int r = 0; r <= nr; ++r)
    for (int i = 0; i < 4; ++i)
      store_be32(words[r * 4 + i], ctx.round_keys[r].data() + i * 4);
  return ctx;
}
void aes_add_key(std::array<byte, 16> &s, const std::array<byte, 16> &rk) {
  for (std::size_t i = 0; i < 16; ++i)
    s[i] ^= rk[i];
}
void aes_sub(std::array<byte, 16> &s, std::span<const byte, 256> box) {
  for (auto &v : s)
    v = box[v];
}
void aes_shift(std::array<byte, 16> &s) {
  auto t = s;
  s[1] = t[5];
  s[5] = t[9];
  s[9] = t[13];
  s[13] = t[1];
  s[2] = t[10];
  s[6] = t[14];
  s[10] = t[2];
  s[14] = t[6];
  s[3] = t[15];
  s[7] = t[3];
  s[11] = t[7];
  s[15] = t[11];
}
void aes_inv_shift(std::array<byte, 16> &s) {
  auto t = s;
  s[1] = t[13];
  s[5] = t[1];
  s[9] = t[5];
  s[13] = t[9];
  s[2] = t[10];
  s[6] = t[14];
  s[10] = t[2];
  s[14] = t[6];
  s[3] = t[7];
  s[7] = t[11];
  s[11] = t[15];
  s[15] = t[3];
}
void aes_mix(std::array<byte, 16> &s) {
  for (int c = 0; c < 4; ++c) {
    byte *col = s.data() + c * 4;
    byte a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
    col[0] = aes_mul(a0, 2) ^ aes_mul(a1, 3) ^ a2 ^ a3;
    col[1] = a0 ^ aes_mul(a1, 2) ^ aes_mul(a2, 3) ^ a3;
    col[2] = a0 ^ a1 ^ aes_mul(a2, 2) ^ aes_mul(a3, 3);
    col[3] = aes_mul(a0, 3) ^ a1 ^ a2 ^ aes_mul(a3, 2);
  }
}
void aes_inv_mix(std::array<byte, 16> &s) {
  for (int c = 0; c < 4; ++c) {
    byte *col = s.data() + c * 4;
    byte a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
    col[0] =
        aes_mul(a0, 14) ^ aes_mul(a1, 11) ^ aes_mul(a2, 13) ^ aes_mul(a3, 9);
    col[1] =
        aes_mul(a0, 9) ^ aes_mul(a1, 14) ^ aes_mul(a2, 11) ^ aes_mul(a3, 13);
    col[2] =
        aes_mul(a0, 13) ^ aes_mul(a1, 9) ^ aes_mul(a2, 14) ^ aes_mul(a3, 11);
    col[3] =
        aes_mul(a0, 11) ^ aes_mul(a1, 13) ^ aes_mul(a2, 9) ^ aes_mul(a3, 14);
  }
}
std::array<byte, 16> aes_enc_block(std::span<const byte, 16> input,
                                   const aes_ctx &ctx,
                                   std::span<const byte, 256> sbox) {
  std::array<byte, 16> s{};
  std::copy(input.begin(), input.end(), s.begin());
  aes_add_key(s, ctx.round_keys[0]);
  for (int r = 1; r < ctx.nr; ++r) {
    aes_sub(s, sbox);
    aes_shift(s);
    aes_mix(s);
    aes_add_key(s, ctx.round_keys[r]);
  }
  aes_sub(s, sbox);
  aes_shift(s);
  aes_add_key(s, ctx.round_keys[ctx.nr]);
  return s;
}
std::array<byte, 16> aes_dec_block(std::span<const byte, 16> input,
                                   const aes_ctx &ctx,
                                   std::span<const byte, 256> inv) {
  std::array<byte, 16> s{};
  std::copy(input.begin(), input.end(), s.begin());
  aes_add_key(s, ctx.round_keys[ctx.nr]);
  for (int r = ctx.nr - 1; r >= 1; --r) {
    aes_inv_shift(s);
    aes_sub(s, inv);
    aes_add_key(s, ctx.round_keys[r]);
    aes_inv_mix(s);
  }
  aes_inv_shift(s);
  aes_sub(s, inv);
  aes_add_key(s, ctx.round_keys[0]);
  return s;
}
bytes block_mode_apply(std::span<const byte> input, std::size_t block,
                       block_mode mode, bytes iv, bool encrypt,
                       const std::function<bytes(std::span<const byte>)> &enc,
                       const std::function<bytes(std::span<const byte>)> &dec,
                       bool pad) {
  bytes data = encrypt ? (pad ? pkcs7_pad(input, block)
                              : bytes(input.begin(), input.end()))
                       : bytes(input.begin(), input.end());
  if (data.size() % block != 0) {
    fail("input is not block-aligned");
  }
  if (iv.empty()) {
    iv.assign(block, 0);
  }
  if (iv.size() != block) {
    fail("invalid IV size");
  }

  bytes out(data.size());
  bytes prev = iv;
  for (std::size_t off = 0; off < data.size(); off += block) {
    bytes cur(data.begin() + static_cast<std::ptrdiff_t>(off),
              data.begin() + static_cast<std::ptrdiff_t>(off + block));
    bytes tmp;
    if (encrypt) {
      switch (mode) {
      case block_mode::ecb:
        tmp = enc(cur);
        break;
      case block_mode::cbc:
        tmp = enc(bxor(cur, prev));
        prev = tmp;
        break;
      case block_mode::pcbc: {
        bytes mixed = bxor(cur, prev);
        tmp = enc(mixed);
        prev = bxor(cur, tmp);
        break;
      }
      case block_mode::cfb: {
        bytes ks = enc(prev);
        tmp = bxor(cur, ks);
        prev = tmp;
        break;
      }
      case block_mode::ofb:
        prev = enc(prev);
        tmp = bxor(cur, prev);
        break;
      case block_mode::ctr: {
        bytes ctr = prev;
        tmp = bxor(cur, enc(ctr));
        for (std::size_t i = block; i-- > 0;) {
          if (++prev[i] != 0) {
            break;
          }
        }
        break;
      }
      }
    } else {
      switch (mode) {
      case block_mode::ecb:
        tmp = dec(cur);
        break;
      case block_mode::cbc: {
        bytes plain = dec(cur);
        tmp = bxor(plain, prev);
        prev = cur;
        break;
      }
      case block_mode::pcbc: {
        bytes plain = dec(cur);
        tmp = bxor(plain, prev);
        prev = bxor(tmp, cur);
        break;
      }
      case block_mode::cfb: {
        bytes ks = enc(prev);
        tmp = bxor(cur, ks);
        prev = cur;
        break;
      }
      case block_mode::ofb:
        prev = enc(prev);
        tmp = bxor(cur, prev);
        break;
      case block_mode::ctr: {
        bytes ctr = prev;
        tmp = bxor(cur, enc(ctr));
        for (std::size_t i = block; i-- > 0;) {
          if (++prev[i] != 0) {
            break;
          }
        }
        break;
      }
      }
    }
    std::copy(tmp.begin(), tmp.end(),
              out.begin() + static_cast<std::ptrdiff_t>(off));
  }

  return (!encrypt && pad) ? pkcs7_unpad(out, block) : out;
}
bytes not_impl(std::string_view name) {
  fail(std::string(name) + " is declared but not implemented in this build");
}

} // namespace
} // namespace regadgets

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif


