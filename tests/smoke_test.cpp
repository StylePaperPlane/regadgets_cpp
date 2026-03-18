#include <cmath>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "regadgets/regadgets.hpp"

namespace {

void require(bool condition, const std::string &message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

bool nearly_equal(double lhs, double rhs, double epsilon = 1e-9) {
  return std::fabs(lhs - rhs) <= epsilon;
}

} // namespace

int main() {
  using namespace regadgets;

  const auto plain = from_string("regadgets_cpp");
  require(to_string(plain) == "regadgets_cpp",
          "string conversion should round-trip");

  const auto base64 = encode_b64(plain);
  require(base64 == "cmVnYWRnZXRzX2NwcA==",
          "base64 encoding should match expected value");
  require(decode_b64(base64) == plain, "base64 decoding should round-trip");

  const auto digest = to_hex(sha256(plain));
  require(
      digest ==
          "99777a7d6ed41f1e6928bfc59531fea599ff9c3d3c7bfeb2d783b19da447b777",
      "sha256 digest should remain stable");

  aes_options options;
  options.mode = block_mode::cbc;
  options.iv = from_hex("00112233445566778899aabbccddeeff");

  const auto key = from_string("0123456789abcdef");
  const auto cipher = aes128_encrypt(plain, key, options);
  const auto roundtrip = aes128_decrypt(cipher, key, options);
  require(roundtrip == plain, "AES-128 CBC should decrypt back to plaintext");

  const aes_params custom_aes_params{std::span<const byte, 256>(aes_default_sbox),
                                     std::span<const byte, 256>(aes_default_inv_sbox),
                                     std::span<const byte, 15>(aes_default_rcon),
                                     10};
  const auto custom_cipher =
      aes128_encrypt(plain, key, custom_aes_params, options);
  require(custom_cipher == cipher,
          "AES custom-params API should match default AES-128 output");
  require(aes128_decrypt(custom_cipher, key, custom_aes_params, options) ==
              plain,
          "AES custom-params API should decrypt back to plaintext");

  const std::array<std::uint32_t, 4> tea_key{0x01234567u, 0x89abcdefu,
                                             0xfedcba98u, 0x76543210u};
  require(to_string(tea_decrypt(tea_encrypt(from_string("tea demo"), tea_key),
                                tea_key)) == "tea demo",
          "TEA byte-stream API should pad and round-trip");
  require(
      to_string(xtea_decrypt(xtea_encrypt(from_string("xtea demo"), tea_key),
                             tea_key)) == "xtea demo",
      "XTEA byte-stream API should pad and round-trip");

  const auto des_plain = from_string("DES stream demo");
  const auto des_key = from_hex("133457799BBCDFF1");
  const auto des_iv = from_hex("0102030405060708");
  const auto des_cipher =
      des_encrypt(des_plain, des_key, block_mode::cbc, des_iv);
  require(des_decrypt(des_cipher, des_key, block_mode::cbc, des_iv) ==
              des_plain,
          "DES byte-stream API should pad and round-trip");

  const auto tdes_key = from_string("0123456789abcdefghijklmn");
  const auto tdes_cipher =
      tripledes_encrypt(des_plain, tdes_key, block_mode::cbc, des_iv);
  require(tripledes_decrypt(tdes_cipher, tdes_key, block_mode::cbc, des_iv) ==
              des_plain,
          "3DES byte-stream API should pad and round-trip");

  const auto blowfish_key = from_string("blowfish-key");
  const auto blowfish_cipher =
      blowfish_encrypt(des_plain, blowfish_key, block_mode::cbc, des_iv);
  require(blowfish_decrypt(blowfish_cipher, blowfish_key, block_mode::cbc,
                           des_iv) == des_plain,
          "Blowfish byte-stream API should pad and round-trip");

  const auto sm4_block = from_hex("0123456789abcdeffedcba9876543210");
  const auto sm4_key = from_hex("0123456789abcdeffedcba9876543210");
  const auto sm4_cipher_block =
      SM4_encrypt(std::span<const byte, 16>(sm4_block.data(), 16),
                  std::span<const byte, 16>(sm4_key.data(), 16));
  require(to_hex(sm4_cipher_block) == "681edf34d206965e86b3e94f536e4246",
          "SM4 block encryption should match the standard vector");
  require(
      to_hex(SM4_decrypt(std::span<const byte, 16>(sm4_cipher_block.data(), 16),
                         std::span<const byte, 16>(sm4_key.data(), 16))) ==
          "0123456789abcdeffedcba9876543210",
      "SM4 block decryption should match the original block");

  MT19937 mt19937(5489u);
  MT19937Predictor predictor;
  predictor.submit(mt19937.sequence(MT19937::state_size));
  require(predictor.ready(),
          "MT19937 predictor should become ready after 624 samples");
  require(predictor.samples_collected() == MT19937::state_size,
          "MT19937 predictor should record 624 samples");
  const auto mt_expected = mt19937.sequence(8);
  const auto mt_predicted = predictor.sequence(8);
  require(mt_predicted == mt_expected,
          "MT19937 predictor should recover state and match future outputs");

  const auto dct = dct_transform(std::vector<double>{1.0, 2.0, 3.0, 4.0});
  const auto idct = idct_transform(dct);
  require(idct.size() == 4, "IDCT output size should match input");
  require(nearly_equal(idct[0], 1.0), "IDCT element 0 should round-trip");
  require(nearly_equal(idct[1], 2.0), "IDCT element 1 should round-trip");
  require(nearly_equal(idct[2], 3.0), "IDCT element 2 should round-trip");
  require(nearly_equal(idct[3], 4.0), "IDCT element 3 should round-trip");

  std::cout << "regadgets smoke tests passed\n";
  return 0;
}


