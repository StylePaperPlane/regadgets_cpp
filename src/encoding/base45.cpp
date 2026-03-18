#include "regadgets/encoding/base45.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
std::string encode_b45(std::span<const byte> input, std::string_view alphabet) {
  return encode_radix(input, alphabet);
}
bytes decode_b45(std::string_view input, std::string_view alphabet) {
  return decode_radix(input, alphabet);
}

} // namespace regadgets
