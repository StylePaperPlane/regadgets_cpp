#include "regadgets/bitwise/data_conversion.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
bytes from_string(std::string_view input) {
  return bytes(input.begin(), input.end());
}
std::string to_string(std::span<const byte> input) {
  return std::string(input.begin(), input.end());
}
std::string to_hex(std::span<const byte> input, bool upper) {
  const char *tab = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  std::string out;
  out.reserve(input.size() * 2);
  for (byte b : input) {
    out.push_back(tab[b >> 4U]);
    out.push_back(tab[b & 0x0FU]);
  }
  return out;
}
bytes from_hex(std::string_view hex) {
  auto hv = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  if (hex.size() % 2 != 0)
    fail("hex input must be even length");
  bytes out(hex.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    int hi = hv(hex[i * 2]), lo = hv(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      fail("invalid hex character");
    out[i] = static_cast<byte>((hi << 4) | lo);
  }
  return out;
}
std::uint16_t bytes_to_word(std::span<const byte> input, bool le) {
  if (input.size() < 2)
    fail("need 2 bytes");
  return le ? static_cast<std::uint16_t>(input[0] | (input[1] << 8U))
            : static_cast<std::uint16_t>((input[0] << 8U) | input[1]);
}
std::uint32_t bytes_to_dword(std::span<const byte> input, bool le) {
  if (input.size() < 4)
    fail("need 4 bytes");
  return le ? load_le32(input.first<4>()) : load_be32(input.first<4>());
}
std::uint64_t bytes_to_qword(std::span<const byte> input, bool le) {
  if (input.size() < 8)
    fail("need 8 bytes");
  std::uint64_t v = 0;
  if (le)
    for (int i = 7; i >= 0; --i)
      v = (v << 8U) | input[static_cast<std::size_t>(i)];
  else
    for (int i = 0; i < 8; ++i)
      v = (v << 8U) | input[static_cast<std::size_t>(i)];
  return v;
}
bytes word_to_bytes(std::uint16_t value, bool le) {
  return le ? bytes{static_cast<byte>(value), static_cast<byte>(value >> 8U)}
            : bytes{static_cast<byte>(value >> 8U), static_cast<byte>(value)};
}
bytes dword_to_bytes(std::uint32_t value, bool le) {
  bytes out(4);
  if (le)
    store_le32(value, out.data());
  else
    store_be32(value, out.data());
  return out;
}
bytes qword_to_bytes(std::uint64_t value, bool le) {
  bytes out(8);
  if (le)
    for (int i = 0; i < 8; ++i)
      out[static_cast<std::size_t>(i)] = static_cast<byte>(value >> (i * 8U));
  else
    store_be64(value, out.data());
  return out;
}
bytes pack_dword(std::span<const std::uint32_t> values, bool le) {
  bytes out;
  out.reserve(values.size() * 4);
  for (auto v : values) {
    auto tmp = dword_to_bytes(v, le);
    out.insert(out.end(), tmp.begin(), tmp.end());
  }
  return out;
}
std::vector<std::uint32_t> unpack_dword(std::span<const byte> input, bool le) {
  if (input.size() % 4 != 0)
    fail("input size must be multiple of 4");
  std::vector<std::uint32_t> out(input.size() / 4);
  for (std::size_t i = 0; i < out.size(); ++i)
    out[i] = bytes_to_dword(input.subspan(i * 4, 4), le);
  return out;
}
std::uint32_t bswap32(std::uint32_t value) noexcept {
  return std::byteswap(value);
}

} // namespace regadgets
