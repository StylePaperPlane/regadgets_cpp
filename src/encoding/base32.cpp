#include "regadgets/encoding/base32.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
std::string encode_b32(std::span<const byte> input, std::string_view alphabet) {
  return encode_pow2(input, alphabet, 5, true);
}
bytes decode_b32(std::string_view input, std::string_view alphabet) {
  return decode_pow2(input, alphabet, 5);
}

} // namespace regadgets
