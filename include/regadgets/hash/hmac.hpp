#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

hmac_result hmac_md5(std::span<const byte> key, std::span<const byte> message);
hmac_result hmac_sha1(std::span<const byte> key, std::span<const byte> message);
hmac_result hmac_sha256(std::span<const byte> key,
                        std::span<const byte> message);

} // namespace regadgets
