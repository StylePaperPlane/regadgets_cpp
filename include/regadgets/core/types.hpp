#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace regadgets {

using byte = std::uint8_t;
using bytes = std::vector<byte>;
using matrix = std::vector<std::vector<double>>;

enum class block_mode {
  ecb,
  cbc,
  pcbc,
  cfb,
  ofb,
  ctr,
};

struct rc4_state {
  std::array<byte, 256> s{};
  std::uint32_t i = 0;
  std::uint32_t j = 0;
};

struct aes_options {
  block_mode mode = block_mode::ecb;
  bytes iv{};
  bool pkcs7_padding = true;
};

struct xxtea_options {
  std::uint32_t rounds_bias = 0;
  std::uint32_t shift = 2;
};

struct hmac_result {
  bytes raw;
  std::string hex;
};

} // namespace regadgets
