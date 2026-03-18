#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

rc4_state rc4_init(std::span<const byte> key);
bytes rc4_keystream(rc4_state state, std::size_t length);
bytes rc4_crypt(rc4_state state, std::span<const byte> input);

} // namespace regadgets
