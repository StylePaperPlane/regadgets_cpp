#include <array>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "regadgets/regadgets.hpp"

namespace {

using regadgets::byte;
using regadgets::bytes;
using regadgets::matrix;

std::string hex_of(std::span<const byte> input) {
  return regadgets::to_hex(input);
}

void print_section(const std::string &title) {
  std::cout << "\n== " << title << " ==\n";
}

void print_matrix(const matrix &input) {
  for (const auto &row : input) {
    std::cout << "  [ ";
    for (double value : row) {
      std::cout << std::fixed << std::setprecision(3) << value << ' ';
    }
    std::cout << "]\n";
  }
}

} // namespace

int main() {
  using namespace regadgets;

  std::cout << std::boolalpha;

  const auto plain = from_string("regadgets_cpp");
  const auto key16 = from_string("0123456789abcdef");
  const auto key32 = from_string("0123456789abcdef0123456789abcdef");

  print_section("Bit Operations And Data Conversion");
  std::cout << "from_string/to_string: " << to_string(plain) << '\n';
  std::cout << "to_hex/from_hex: " << to_string(from_hex(to_hex(plain)))
            << '\n';
  std::cout << "rol(0x12345678, 5): 0x" << std::hex
            << rol<std::uint32_t>(0x12345678u, 5) << '\n';
  std::cout << "ror(0x12345678, 5): 0x" << std::hex
            << ror<std::uint32_t>(0x12345678u, 5) << '\n';
  std::cout << "bytes_to_word LE: 0x" << std::hex
            << bytes_to_word(from_hex("3412")) << '\n';
  std::cout << "bytes_to_dword BE: 0x" << std::hex
            << bytes_to_dword(from_hex("12345678"), false) << '\n';
  std::cout << "bytes_to_qword BE: 0x" << std::hex
            << bytes_to_qword(from_hex("0123456789abcdef"), false) << '\n';
  std::cout << "word_to_bytes: " << hex_of(word_to_bytes(0x1234u)) << '\n';
  std::cout << "dword_to_bytes: " << hex_of(dword_to_bytes(0x12345678u))
            << '\n';
  std::cout << "qword_to_bytes: "
            << hex_of(qword_to_bytes(0x0123456789abcdefULL)) << '\n';
  std::cout << "pack_dword: "
            << hex_of(pack_dword(
                   std::array<std::uint32_t, 2>{0x11223344u, 0x55667788u}))
            << '\n';
  const auto unpacked = unpack_dword(from_hex("4433221188776655"));
  std::cout << "unpack_dword[0]: 0x" << std::hex << unpacked[0] << ", [1]: 0x"
            << unpacked[1] << '\n';
  std::cout << "bswap32: 0x" << std::hex << bswap32(0x12345678u) << '\n';
  std::cout << "bxor: "
            << hex_of(bxor(from_hex("aabbccdd"), from_hex("01020304"))) << '\n';
  std::cout << "bxor_cycle: " << hex_of(bxor_cycle(plain, from_string("key")))
            << '\n';
  std::cout << "bxorr roundtrip: "
            << to_string(bxorr_dec(bxorr_enc(plain, 0x5a), 0x5a)) << '\n';
  std::cout << "bxorl roundtrip: "
            << to_string(bxorl_dec(bxorl_enc(plain, 0x5a), 0x5a)) << '\n';

  print_section("Encoding Algorithms");
  const auto b16 = encode_b16(plain);
  const auto b32 = encode_b32(plain);
  const auto b45 = encode_b45(plain);
  const auto b58 = encode_b58(plain);
  const auto b62 = encode_b62(plain);
  const auto b64 = encode_b64(plain);
  const auto b85 = encode_b85(plain);
  const auto b91 = encode_b91(plain);
  const auto b92 = encode_b92(plain);
  std::cout << "Base16: " << b16 << " -> " << to_string(decode_b16(b16))
            << '\n';
  std::cout << "Base32: " << b32 << " -> " << to_string(decode_b32(b32))
            << '\n';
  std::cout << "Base45: " << b45 << " -> " << to_string(decode_b45(b45))
            << '\n';
  std::cout << "Base58: " << b58 << " -> " << to_string(decode_b58(b58))
            << '\n';
  std::cout << "Base62: " << b62 << " -> " << to_string(decode_b62(b62))
            << '\n';
  std::cout << "Base64: " << b64 << " -> " << to_string(decode_b64(b64))
            << '\n';
  std::cout << "Base85: " << b85 << " -> " << to_string(decode_b85(b85))
            << '\n';
  std::cout << "Base91: " << b91 << " -> " << to_string(decode_b91(b91))
            << '\n';
  std::cout << "Base92: " << b92 << " -> " << to_string(decode_b92(b92))
            << '\n';
#ifdef REGADGETS_ENABLE_BASE2048
  std::array<char32_t, 2048> alphabet2048{};
  for (std::size_t i = 0; i < alphabet2048.size(); ++i) {
    alphabet2048[i] = static_cast<char32_t>(0x4e00 + i);
  }
  const auto b2048 = encode_b2048(plain, alphabet2048);
  std::cout << "Base2048 length: " << std::dec << b2048.size() << " -> "
            << to_string(decode_b2048(b2048, alphabet2048)) << '\n';
#endif

  print_section("Stream Ciphers");
  const auto rc4_state0 = rc4_init(from_string("rc4-key"));
  const auto rc4_keystream_value = rc4_keystream(rc4_state0, 16);
  const auto rc4_cipher = rc4_crypt(rc4_init(from_string("rc4-key")), plain);
  const auto rc4_plain =
      rc4_crypt(rc4_init(from_string("rc4-key")), rc4_cipher);
  std::cout << "RC4 keystream: " << hex_of(rc4_keystream_value) << '\n';
  std::cout << "RC4 roundtrip: " << to_string(rc4_plain) << '\n';

  const auto salsa_key = from_hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const auto salsa_nonce = from_hex("0001020304050607");
  const auto salsa_cipher = salsa20_crypt(salsa_key, salsa_nonce, 1, plain);
  const auto salsa_plain =
      salsa20_crypt(salsa_key, salsa_nonce, 1, salsa_cipher);
  std::cout << "Salsa20 roundtrip: " << to_string(salsa_plain) << '\n';

  const auto chacha_nonce = from_hex("000102030405060708090a0b");
  const auto chacha_cipher = chacha20_crypt(salsa_key, chacha_nonce, 1, plain);
  const auto chacha_plain =
      chacha20_crypt(salsa_key, chacha_nonce, 1, chacha_cipher);
  std::cout << "ChaCha20 roundtrip: " << to_string(chacha_plain) << '\n';

  print_section("Block Ciphers And Symmetric Crypto");
  const std::array<std::uint32_t, 4> tea_key{0x01234567u, 0x89abcdefu,
                                             0xfedcba98u, 0x76543210u};
  const auto tea_bytes = from_string("tea demo");
  const auto tea_cipher = tea_encrypt(tea_bytes, tea_key);
  const auto tea_plain = tea_decrypt(tea_cipher, tea_key);
  std::cout << "TEA byte-stream roundtrip: " << to_string(tea_plain) << '\n';

  const auto xtea_bytes = from_string("xtea demo");
  const auto xtea_cipher = xtea_encrypt(xtea_bytes, tea_key);
  const auto xtea_plain = xtea_decrypt(xtea_cipher, tea_key);
  std::cout << "XTEA byte-stream roundtrip: " << to_string(xtea_plain) << '\n';

  xxtea_options xxtea_opts;
  const auto xxtea_cipher = xxtea_encrypt(plain, tea_key, xxtea_opts);
  const auto xxtea_plain = xxtea_decrypt(xxtea_cipher, tea_key, xxtea_opts);
  std::cout << "XXTEA roundtrip: " << to_string(xxtea_plain) << '\n';

  const auto rc5_cipher = rc5_encrypt(plain, from_string("rc5-key"));
  const auto rc5_plain = rc5_decrypt(rc5_cipher, from_string("rc5-key"));
  std::cout << "RC5 roundtrip: " << to_string(rc5_plain) << '\n';

  const auto des_plain = from_string("DES-test");
  const auto des_key = from_hex("133457799BBCDFF1");
  const auto des_cipher = des_encrypt(des_plain, des_key);
  std::cout << "DES roundtrip: " << to_string(des_decrypt(des_cipher, des_key))
            << '\n';

  const auto tdes_key = from_string("0123456789abcdefghijklmn");
  const auto tdes_cipher = tripledes_encrypt(des_plain, tdes_key);
  std::cout << "3DES roundtrip: "
            << to_string(tripledes_decrypt(tdes_cipher, tdes_key)) << '\n';

  aes_options aes_opts;
  aes_opts.mode = block_mode::cbc;
  aes_opts.iv = from_hex("00112233445566778899aabbccddeeff");
  const auto aes128_cipher = aes128_encrypt(plain, key16, aes_opts);
  const auto aes128_plain = aes128_decrypt(aes128_cipher, key16, aes_opts);
  const auto aes256_cipher = aes256_encrypt(plain, key32, aes_opts);
  const auto aes256_plain = aes256_decrypt(aes256_cipher, key32, aes_opts);
  std::cout << "AES128 roundtrip: " << to_string(aes128_plain) << '\n';
  std::cout << "AES256 roundtrip: " << to_string(aes256_plain) << '\n';
  const auto aes_string_cipher =
      aes_encrypt("hello world", "0123456789abcdef", aes_opts);
  const auto aes_string_plain =
      aes_decrypt(aes_string_cipher, "0123456789abcdef", aes_opts);
  std::cout << "AES string helper: " << aes_string_plain << '\n';

  const auto blowfish_cipher =
      blowfish_encrypt(des_plain, from_string("blowfish-key"));
  const auto blowfish_plain =
      blowfish_decrypt(blowfish_cipher, from_string("blowfish-key"));
  std::cout << "Blowfish roundtrip: " << to_string(blowfish_plain) << '\n';

  const auto sm4_key = from_hex("0123456789abcdeffedcba9876543210");
  const auto sm4_block = from_hex("0123456789abcdeffedcba9876543210");
  const auto sm4_enc =
      SM4_encrypt(std::span<const byte, 16>(sm4_block.data(), 16),
                  std::span<const byte, 16>(sm4_key.data(), 16));
  const auto sm4_dec =
      SM4_decrypt(std::span<const byte, 16>(sm4_enc.data(), 16),
                  std::span<const byte, 16>(sm4_key.data(), 16));
  std::cout << "SM4 block encrypt: " << hex_of(sm4_enc) << '\n';
  std::cout << "SM4 block decrypt: " << hex_of(sm4_dec) << '\n';
  const auto sm4_ecb_cipher =
      sm4_ecb_encrypt(plain, std::span<const byte, 16>(sm4_key.data(), 16));
  std::cout << "SM4 ECB roundtrip: "
            << to_string(sm4_ecb_decrypt(
                   sm4_ecb_cipher,
                   std::span<const byte, 16>(sm4_key.data(), 16)))
            << '\n';
  const auto sm4_iv = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto sm4_cbc_cipher =
      sm4_cbc_encrypt(plain, std::span<const byte, 16>(sm4_key.data(), 16),
                      std::span<const byte, 16>(sm4_iv.data(), 16));
  std::cout << "SM4 CBC roundtrip: "
            << to_string(sm4_cbc_decrypt(
                   sm4_cbc_cipher,
                   std::span<const byte, 16>(sm4_key.data(), 16),
                   std::span<const byte, 16>(sm4_iv.data(), 16)))
            << '\n';

  print_section("Hash And Digest Algorithms");
  std::cout << "MD5: " << to_hex(md5(plain)) << '\n';
  std::cout << "SHA1: " << to_hex(sha1(plain)) << '\n';
  std::cout << "SHA256: " << to_hex(sha256(plain)) << '\n';
  std::cout << "SHA512: " << to_hex(sha512(plain)) << '\n';
  std::cout << "CRC32: 0x" << std::hex << crc32(plain) << '\n';
  std::cout << "CRC64: 0x" << std::hex << crc64(plain) << '\n';
  std::cout << "Adler32: 0x" << std::hex << adler32(plain) << '\n';
  std::cout << "HMAC-MD5: " << hmac_md5(from_string("secret"), plain).hex
            << '\n';
  std::cout << "HMAC-SHA1: " << hmac_sha1(from_string("secret"), plain).hex
            << '\n';
  std::cout << "HMAC-SHA256: " << hmac_sha256(from_string("secret"), plain).hex
            << '\n';

  print_section("Math And Matrix Algorithms");
  const auto dct = dct_transform(std::vector<double>{1.0, 2.0, 3.0, 4.0});
  const auto idct = idct_transform(dct);
  std::cout << "DCT[0]: " << std::dec << dct[0] << ", IDCT[0]: " << idct[0]
            << '\n';
  const matrix lhs{{1.0, 2.0}, {3.0, 4.0}};
  const matrix rhs{{5.0, 6.0}, {7.0, 8.0}};
  const auto multiplied = matrix_multiply(lhs, rhs);
  const auto square = generate_matrix_square(3, 2.0, 0.5);
  const auto determinant = matrix_determinant(lhs);
  const auto inverse = matrix_inverse(lhs);
  const auto flattened = flat_matrix(square);
  std::cout << "Matrix multiply:\n";
  print_matrix(multiplied);
  std::cout << "Matrix determinant: " << determinant << '\n';
  std::cout << "Matrix inverse:\n";
  print_matrix(inverse);
  std::cout << "Flattened square matrix size: " << flattened.size() << '\n';

  print_section("Pseudo Random Number Generators");
  GLIBCRand glibc_rand(12345);
  WindowsRand windows_rand(12345);
  MT19937 mt19937(5489u);
  MT19937Predictor predictor;
  std::cout << "GLIBC rand next: " << glibc_rand.next() << '\n';
  const auto glibc_seq = glibc_rand.sequence(3);
  std::cout << "GLIBC rand sequence: " << glibc_seq[0] << ", " << glibc_seq[1]
            << ", " << glibc_seq[2] << '\n';
  std::cout << "Windows rand next: " << windows_rand.next() << '\n';
  const auto windows_seq = windows_rand.sequence(3);
  std::cout << "Windows rand sequence: " << windows_seq[0] << ", "
            << windows_seq[1] << ", " << windows_seq[2] << '\n';
  std::cout << "MT19937 next: " << mt19937.next() << '\n';
  predictor.submit(mt19937.sequence(MT19937::state_size));
  const auto mt_expected = mt19937.sequence(3);
  const auto mt_predicted = predictor.sequence(3);
  std::cout << "MT19937 predicted sequence: " << mt_predicted[0] << ", "
            << mt_predicted[1] << ", " << mt_predicted[2] << '\n';
  std::cout << "MT19937 prediction matches: "
            << (mt_predicted == mt_expected) << '\n';

  print_section("Reverse Engineering Helpers");
  const auto [sbox, inverse_sbox] = generate_sbox({});
  const auto transformed = sbox_transform(from_hex("00112233"), sbox);
  const auto restored = sbox_transform(transformed, inverse_sbox);
  std::cout << "S-box transformed: " << hex_of(transformed) << '\n';
  std::cout << "S-box restored: " << hex_of(restored) << '\n';

  return 0;
}

