#include "regadgets/hash/checksum.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
std::uint32_t crc32(std::span<const byte> input, std::uint32_t seed) {
  std::uint32_t crc = seed;
  for (byte b : input) {
    crc ^= b;
    for (int i = 0; i < 8; ++i)
      crc = (crc >> 1U) ^ (0xEDB88320u & (-(crc & 1U)));
  }
  return ~crc;
}
std::uint64_t crc64(std::span<const byte> input, std::uint64_t seed) {
  std::uint64_t crc = seed;
  for (byte b : input) {
    crc ^= b;
    for (int i = 0; i < 8; ++i)
      crc = (crc >> 1U) ^
            (0xC96C5795D7870F42ull & (-(static_cast<std::int64_t>(crc & 1U))));
  }
  return ~crc;
}
std::uint32_t adler32(std::span<const byte> input) {
  std::uint32_t a = 1, b = 0;
  for (byte x : input) {
    a = (a + x) % 65521U;
    b = (b + a) % 65521U;
  }
  return (b << 16U) | a;
}

} // namespace regadgets
