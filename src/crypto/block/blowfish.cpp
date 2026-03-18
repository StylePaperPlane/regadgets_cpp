#include "regadgets/crypto/block/blowfish.hpp"

#include "common.hpp"

namespace regadgets {
namespace {

struct blowfish_state {
  std::array<std::uint32_t, 18> p{};
  std::array<std::array<std::uint32_t, 256>, 4> s{};
};

double blowfish_series(int m, int n) {
  double sum = 0.0;
  for (int k = 0; k <= n; ++k) {
    const int denom = 8 * k + m;
    std::uint64_t mod = 1;
    std::uint64_t base = 16 % denom;
    int exp = n - k;
    while (exp > 0) {
      if (exp & 1) {
        mod = (mod * base) % denom;
      }
      base = (base * base) % denom;
      exp >>= 1;
    }
    sum += static_cast<double>(mod) / static_cast<double>(denom);
    sum -= std::floor(sum);
  }

  for (int k = n + 1;; ++k) {
    const double term = std::pow(16.0, static_cast<double>(n - k)) /
                        static_cast<double>(8 * k + m);
    if (term < 1e-17) {
      break;
    }
    sum += term;
    sum -= std::floor(sum);
  }

  return sum;
}

int pi_hex_digit(int index) {
  double value = 4.0 * blowfish_series(1, index) -
                 2.0 * blowfish_series(4, index) - blowfish_series(5, index) -
                 blowfish_series(6, index);
  value -= std::floor(value);
  return static_cast<int>(value * 16.0);
}

std::uint32_t pi_hex_word(int word_index) {
  std::uint32_t value = 0;
  for (int nibble = 0; nibble < 8; ++nibble) {
    value = (value << 4U) |
            static_cast<std::uint32_t>(pi_hex_digit(word_index * 8 + nibble));
  }
  return value;
}

const blowfish_state &blowfish_initial_state() {
  static const blowfish_state state = [] {
    blowfish_state out;
    int word = 0;
    for (auto &p : out.p) {
      p = pi_hex_word(word++);
    }
    for (auto &box : out.s) {
      for (auto &value : box) {
        value = pi_hex_word(word++);
      }
    }
    return out;
  }();
  return state;
}

std::uint32_t blowfish_f(const blowfish_state &state, std::uint32_t value) {
  const std::uint8_t a = static_cast<std::uint8_t>(value >> 24U);
  const std::uint8_t b = static_cast<std::uint8_t>(value >> 16U);
  const std::uint8_t c = static_cast<std::uint8_t>(value >> 8U);
  const std::uint8_t d = static_cast<std::uint8_t>(value);
  return ((state.s[0][a] + state.s[1][b]) ^ state.s[2][c]) + state.s[3][d];
}

void blowfish_encrypt_words(const blowfish_state &state, std::uint32_t &lhs,
                            std::uint32_t &rhs) {
  for (int i = 0; i < 16; ++i) {
    lhs ^= state.p[i];
    rhs ^= blowfish_f(state, lhs);
    std::swap(lhs, rhs);
  }
  std::swap(lhs, rhs);
  rhs ^= state.p[16];
  lhs ^= state.p[17];
}

void blowfish_decrypt_words(const blowfish_state &state, std::uint32_t &lhs,
                            std::uint32_t &rhs) {
  for (int i = 17; i > 1; --i) {
    lhs ^= state.p[i];
    rhs ^= blowfish_f(state, lhs);
    std::swap(lhs, rhs);
  }
  std::swap(lhs, rhs);
  rhs ^= state.p[1];
  lhs ^= state.p[0];
}

blowfish_state blowfish_expand(std::span<const byte> key) {
  if (key.empty()) {
    fail("Blowfish key must not be empty");
  }
  if (key.size() > 56) {
    fail("Blowfish key must be at most 56 bytes");
  }

  blowfish_state state = blowfish_initial_state();
  std::size_t index = 0;
  for (auto &p : state.p) {
    std::uint32_t word = 0;
    for (int i = 0; i < 4; ++i) {
      word = (word << 8U) | key[index % key.size()];
      ++index;
    }
    p ^= word;
  }

  std::uint32_t lhs = 0;
  std::uint32_t rhs = 0;
  for (std::size_t i = 0; i < state.p.size(); i += 2) {
    blowfish_encrypt_words(state, lhs, rhs);
    state.p[i] = lhs;
    state.p[i + 1] = rhs;
  }
  for (auto &box : state.s) {
    for (std::size_t i = 0; i < box.size(); i += 2) {
      blowfish_encrypt_words(state, lhs, rhs);
      box[i] = lhs;
      box[i + 1] = rhs;
    }
  }

  return state;
}

bytes blowfish_block_encrypt(std::span<const byte> block,
                             std::span<const byte> key) {
  blowfish_state state = blowfish_expand(key);
  std::uint32_t lhs = load_be32(block.subspan(0, 4));
  std::uint32_t rhs = load_be32(block.subspan(4, 4));
  blowfish_encrypt_words(state, lhs, rhs);
  bytes out(8);
  store_be32(lhs, out.data());
  store_be32(rhs, out.data() + 4);
  return out;
}

bytes blowfish_block_decrypt(std::span<const byte> block,
                             std::span<const byte> key) {
  blowfish_state state = blowfish_expand(key);
  std::uint32_t lhs = load_be32(block.subspan(0, 4));
  std::uint32_t rhs = load_be32(block.subspan(4, 4));
  blowfish_decrypt_words(state, lhs, rhs);
  bytes out(8);
  store_be32(lhs, out.data());
  store_be32(rhs, out.data() + 4);
  return out;
}

} // namespace

bytes blowfish_encrypt(std::span<const byte> input, std::span<const byte> key,
                       block_mode mode, std::span<const byte> iv) {
  return block_mode_apply(
      input, 8, mode, bytes(iv.begin(), iv.end()), true,
      [&](std::span<const byte> block) {
        return blowfish_block_encrypt(block, key);
      },
      [&](std::span<const byte> block) {
        return blowfish_block_decrypt(block, key);
      },
      true);
}

bytes blowfish_decrypt(std::span<const byte> input, std::span<const byte> key,
                       block_mode mode, std::span<const byte> iv) {
  return block_mode_apply(
      input, 8, mode, bytes(iv.begin(), iv.end()), false,
      [&](std::span<const byte> block) {
        return blowfish_block_encrypt(block, key);
      },
      [&](std::span<const byte> block) {
        return blowfish_block_decrypt(block, key);
      },
      true);
}

} // namespace regadgets
