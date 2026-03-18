#include "regadgets/crypto/block/aes.hpp"

#include "common.hpp"

namespace regadgets {
namespace {

bytes aes_encrypt_impl(std::span<const byte> input, std::span<const byte> key,
                       const aes_params &params, aes_options options,
                       std::size_t expected_key_size) {
  if (key.size() != expected_key_size) {
    fail(expected_key_size == 16 ? "AES-128 requires 16-byte key"
                                 : "AES-256 requires 32-byte key");
  }

  const auto ctx = aes_expand_key(key, params);
  return block_mode_apply(
      input, 16, options.mode, options.iv, true,
      [&](std::span<const byte> block) {
        const auto encrypted = aes_enc_block(
            std::span<const byte, 16>(block.data(), 16), ctx, params.sbox);
        return bytes(encrypted.begin(), encrypted.end());
      },
      [&](std::span<const byte> block) {
        const auto decrypted = aes_dec_block(
            std::span<const byte, 16>(block.data(), 16), ctx, params.inv_sbox);
        return bytes(decrypted.begin(), decrypted.end());
      },
      options.pkcs7_padding);
}

bytes aes_decrypt_impl(std::span<const byte> input, std::span<const byte> key,
                       const aes_params &params, aes_options options,
                       std::size_t expected_key_size) {
  if (key.size() != expected_key_size) {
    fail(expected_key_size == 16 ? "AES-128 requires 16-byte key"
                                 : "AES-256 requires 32-byte key");
  }

  const auto ctx = aes_expand_key(key, params);
  return block_mode_apply(
      input, 16, options.mode, options.iv, false,
      [&](std::span<const byte> block) {
        const auto encrypted = aes_enc_block(
            std::span<const byte, 16>(block.data(), 16), ctx, params.sbox);
        return bytes(encrypted.begin(), encrypted.end());
      },
      [&](std::span<const byte> block) {
        const auto decrypted = aes_dec_block(
            std::span<const byte, 16>(block.data(), 16), ctx, params.inv_sbox);
        return bytes(decrypted.begin(), decrypted.end());
      },
      options.pkcs7_padding);
}

} // namespace

bytes aes128_encrypt(std::span<const byte> input, std::span<const byte> key,
                     const aes_params &params, aes_options options) {
  return aes_encrypt_impl(input, key, params, options, 16);
}

bytes aes128_decrypt(std::span<const byte> input, std::span<const byte> key,
                     const aes_params &params, aes_options options) {
  return aes_decrypt_impl(input, key, params, options, 16);
}

bytes aes128_encrypt(std::span<const byte> input, std::span<const byte> key,
                     aes_options options) {
  return aes128_encrypt(input, key, aes128_default_params, options);
}

bytes aes128_decrypt(std::span<const byte> input, std::span<const byte> key,
                     aes_options options) {
  return aes128_decrypt(input, key, aes128_default_params, options);
}

bytes aes256_encrypt(std::span<const byte> input, std::span<const byte> key,
                     const aes_params &params, aes_options options) {
  return aes_encrypt_impl(input, key, params, options, 32);
}

bytes aes256_decrypt(std::span<const byte> input, std::span<const byte> key,
                     const aes_params &params, aes_options options) {
  return aes_decrypt_impl(input, key, params, options, 32);
}

bytes aes256_encrypt(std::span<const byte> input, std::span<const byte> key,
                     aes_options options) {
  return aes256_encrypt(input, key, aes256_default_params, options);
}

bytes aes256_decrypt(std::span<const byte> input, std::span<const byte> key,
                     aes_options options) {
  return aes256_decrypt(input, key, aes256_default_params, options);
}

std::string aes_encrypt(std::string_view input, std::string_view key,
                        aes_options options, bool input_is_hex,
                        bool output_hex) {
  bytes data = input_is_hex ? from_hex(input) : from_string(input);
  bytes key_bytes =
      (key.size() == 32 || key.size() == 64) ? from_hex(key) : from_string(key);
  bytes cipher =
      key_bytes.size() <= 16
          ? aes128_encrypt(data,
                           bytes(key_bytes.begin(),
                                 key_bytes.begin() + std::min<std::size_t>(
                                                         16, key_bytes.size())),
                           options)
          : aes256_encrypt(data,
                           bytes(key_bytes.begin(), key_bytes.begin() + 32),
                           options);
  return output_hex ? to_hex(cipher) : to_string(cipher);
}

std::string aes_decrypt(std::string_view input, std::string_view key,
                        aes_options options, bool input_is_hex,
                        bool output_hex) {
  bytes data = input_is_hex ? from_hex(input) : from_string(input);
  bytes key_bytes =
      (key.size() == 32 || key.size() == 64) ? from_hex(key) : from_string(key);
  bytes plain =
      key_bytes.size() <= 16
          ? aes128_decrypt(data,
                           bytes(key_bytes.begin(),
                                 key_bytes.begin() + std::min<std::size_t>(
                                                         16, key_bytes.size())),
                           options)
          : aes256_decrypt(data,
                           bytes(key_bytes.begin(), key_bytes.begin() + 32),
                           options);
  return output_hex ? to_hex(plain) : to_string(plain);
}

} // namespace regadgets
