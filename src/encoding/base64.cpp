#include "regadgets/encoding/base64.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
std::string encode_b64(std::span<const byte> input, std::string_view alphabet) {
  return encode_pow2(input, alphabet, 6, true);
}
bytes decode_b64(std::string_view input, std::string_view alphabet) {
  return decode_pow2(input, alphabet, 6);
}

} // namespace regadgets
