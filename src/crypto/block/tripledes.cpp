#include "regadgets/crypto/block/tripledes.hpp"

#include "common.hpp"

namespace regadgets {
namespace {

constexpr std::array<int, 64> kDesIp = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
constexpr std::array<int, 64> kDesFp = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25};
constexpr std::array<int, 48> kDesE = {
    32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
constexpr std::array<int, 32> kDesP = {
    16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
    2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25};
constexpr std::array<int, 56> kDesPc1 = {
    57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
    35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
    46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};
constexpr std::array<int, 48> kDesPc2 = {
    14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
    26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
constexpr std::array<int, 16> kDesShifts = {1, 1, 2, 2, 2, 2, 2, 2,
                                            1, 2, 2, 2, 2, 2, 2, 1};
constexpr std::array<std::array<std::array<int, 16>, 4>, 8> kDesSBoxes = {{
    {{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
      {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
      {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
      {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}}},
    {{{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
      {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
      {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
      {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}}},
    {{{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
      {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
      {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
      {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}}},
    {{{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
      {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
      {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
      {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}}},
    {{{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
      {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
      {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
      {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}}},
    {{{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
      {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
      {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
      {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}}},
    {{{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
      {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
      {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
      {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}}},
    {{{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
      {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
      {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
      {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}},
}};

template <std::size_t N>
std::uint64_t permute_bits(std::uint64_t value, const std::array<int, N> &table,
                           int input_bits) {
  std::uint64_t out = 0;
  for (int position : table) {
    out <<= 1U;
    out |= (value >> (input_bits - position)) & 1ULL;
  }
  return out;
}

std::uint32_t rotate_left28(std::uint32_t value, int shift) {
  value &= 0x0FFFFFFFu;
  return ((value << shift) | (value >> (28 - shift))) & 0x0FFFFFFFu;
}

std::array<std::uint64_t, 16> des_subkeys(std::span<const byte> key) {
  std::uint64_t key64 = load_be64(key);
  std::uint64_t permuted = permute_bits(key64, kDesPc1, 64);
  std::uint32_t c = static_cast<std::uint32_t>(permuted >> 28U) & 0x0FFFFFFFu;
  std::uint32_t d = static_cast<std::uint32_t>(permuted) & 0x0FFFFFFFu;

  std::array<std::uint64_t, 16> subkeys{};
  for (std::size_t round = 0; round < subkeys.size(); ++round) {
    c = rotate_left28(c, kDesShifts[round]);
    d = rotate_left28(d, kDesShifts[round]);
    const std::uint64_t joined = (static_cast<std::uint64_t>(c) << 28U) | d;
    subkeys[round] = permute_bits(joined, kDesPc2, 56);
  }
  return subkeys;
}

std::uint32_t des_feistel(std::uint32_t rhs, std::uint64_t subkey) {
  std::uint64_t expanded = permute_bits(rhs, kDesE, 32);
  expanded ^= subkey;

  std::uint32_t out = 0;
  for (int box = 0; box < 8; ++box) {
    const std::uint8_t chunk =
        static_cast<std::uint8_t>((expanded >> (42 - 6 * box)) & 0x3Fu);
    const int row = ((chunk & 0x20U) >> 4U) | (chunk & 0x01U);
    const int col = (chunk >> 1U) & 0x0FU;
    out = (out << 4U) | static_cast<std::uint32_t>(kDesSBoxes[box][row][col]);
  }

  return static_cast<std::uint32_t>(permute_bits(out, kDesP, 32));
}

std::uint64_t des_process_block(std::uint64_t block,
                                const std::array<std::uint64_t, 16> &subkeys,
                                bool encrypt) {
  std::uint64_t permuted = permute_bits(block, kDesIp, 64);
  std::uint32_t lhs = static_cast<std::uint32_t>(permuted >> 32U);
  std::uint32_t rhs = static_cast<std::uint32_t>(permuted);

  for (int round = 0; round < 16; ++round) {
    const std::uint32_t next_lhs = rhs;
    const auto &subkey = encrypt ? subkeys[round] : subkeys[15 - round];
    const std::uint32_t next_rhs = lhs ^ des_feistel(rhs, subkey);
    lhs = next_lhs;
    rhs = next_rhs;
  }

  const std::uint64_t preoutput =
      (static_cast<std::uint64_t>(rhs) << 32U) | lhs;
  return permute_bits(preoutput, kDesFp, 64);
}

bytes des_block_encrypt(std::span<const byte> block,
                        std::span<const byte> key) {
  const auto subkeys = des_subkeys(key);
  const std::uint64_t value =
      des_process_block(load_be64(block), subkeys, true);
  bytes out(8);
  store_be64(value, out.data());
  return out;
}

bytes des_block_decrypt(std::span<const byte> block,
                        std::span<const byte> key) {
  const auto subkeys = des_subkeys(key);
  const std::uint64_t value =
      des_process_block(load_be64(block), subkeys, false);
  bytes out(8);
  store_be64(value, out.data());
  return out;
}

bytes tripledes_block_encrypt(std::span<const byte> block,
                              std::span<const byte> key) {
  bytes key1(key.begin(), key.begin() + 8);
  bytes key2(key.begin() + 8, key.begin() + 16);
  bytes key3 =
      key.size() == 24 ? bytes(key.begin() + 16, key.begin() + 24) : key1;
  return des_block_encrypt(
      des_block_decrypt(des_block_encrypt(block, key1), key2), key3);
}

bytes tripledes_block_decrypt(std::span<const byte> block,
                              std::span<const byte> key) {
  bytes key1(key.begin(), key.begin() + 8);
  bytes key2(key.begin() + 8, key.begin() + 16);
  bytes key3 =
      key.size() == 24 ? bytes(key.begin() + 16, key.begin() + 24) : key1;
  return des_block_decrypt(
      des_block_encrypt(des_block_decrypt(block, key3), key2), key1);
}

} // namespace

bytes tripledes_encrypt(std::span<const byte> input, std::span<const byte> key,
                        block_mode mode, std::span<const byte> iv) {
  if (key.size() != 16 && key.size() != 24) {
    fail("3DES requires a 16-byte or 24-byte key");
  }
  return block_mode_apply(
      input, 8, mode, bytes(iv.begin(), iv.end()), true,
      [&](std::span<const byte> block) {
        return tripledes_block_encrypt(block, key);
      },
      [&](std::span<const byte> block) {
        return tripledes_block_decrypt(block, key);
      },
      true);
}

bytes tripledes_decrypt(std::span<const byte> input, std::span<const byte> key,
                        block_mode mode, std::span<const byte> iv) {
  if (key.size() != 16 && key.size() != 24) {
    fail("3DES requires a 16-byte or 24-byte key");
  }
  return block_mode_apply(
      input, 8, mode, bytes(iv.begin(), iv.end()), false,
      [&](std::span<const byte> block) {
        return tripledes_block_encrypt(block, key);
      },
      [&](std::span<const byte> block) {
        return tripledes_block_decrypt(block, key);
      },
      true);
}

} // namespace regadgets
