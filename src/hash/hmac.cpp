#include "regadgets/hash/hmac.hpp"

#include "src/crypto/block/common.hpp"

namespace regadgets {

static bytes hmac_impl(std::span<const byte> key, std::span<const byte> message,
                       const std::function<bytes(std::span<const byte>)> &hash,
                       std::size_t block) {
  bytes k(key.begin(), key.end());
  if (k.size() > block) {
    k = hash(k);
  }

  k.resize(block, 0);

  bytes ipad(block, 0x36);
  bytes opad(block, 0x5C);
  for (std::size_t i = 0; i < block; ++i) {
    ipad[i] ^= k[i];
    opad[i] ^= k[i];
  }

  bytes inner = ipad;
  inner.insert(inner.end(), message.begin(), message.end());
  bytes inner_hash = hash(inner);

  bytes outer = opad;
  outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
  return hash(outer);
}

hmac_result hmac_md5(std::span<const byte> key, std::span<const byte> message) {
  bytes raw = hmac_impl(key, message, md5, 64);
  return {raw, to_hex(raw)};
}

hmac_result hmac_sha1(std::span<const byte> key,
                      std::span<const byte> message) {
  bytes raw = hmac_impl(key, message, sha1, 64);
  return {raw, to_hex(raw)};
}

hmac_result hmac_sha256(std::span<const byte> key,
                        std::span<const byte> message) {
  bytes raw = hmac_impl(key, message, sha256, 64);
  return {raw, to_hex(raw)};
}

} // namespace regadgets
