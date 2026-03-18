#include "regadgets/encoding/base85.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
std::string encode_b85(std::span<const byte> input, std::string_view alphabet) {
  static constexpr std::string_view ascii85 =
      "!\"#$%&'()*+,-./"
      "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";
  return encode_radix(input, alphabet.empty() ? ascii85 : alphabet);
}
bytes decode_b85(std::string_view input, std::string_view alphabet) {
  static constexpr std::string_view ascii85 =
      "!\"#$%&'()*+,-./"
      "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";
  return decode_radix(input, alphabet.empty() ? ascii85 : alphabet);
}

} // namespace regadgets
