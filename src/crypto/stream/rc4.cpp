#include "regadgets/crypto/stream/rc4.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
rc4_state rc4_init(std::span<const byte> key) {
  if (key.empty())
    fail("rc4 key must not be empty");
  rc4_state state;
  for (std::size_t i = 0; i < state.s.size(); ++i)
    state.s[i] = static_cast<byte>(i);
  std::uint32_t j = 0;
  for (std::size_t i = 0; i < state.s.size(); ++i) {
    j = (j + state.s[i] + key[i % key.size()]) & 0xFFU;
    std::swap(state.s[i], state.s[j]);
  }
  return state;
}
bytes rc4_keystream(rc4_state state, std::size_t length) {
  bytes out(length);
  for (std::size_t k = 0; k < length; ++k) {
    state.i = (state.i + 1) & 0xFFU;
    state.j = (state.j + state.s[state.i]) & 0xFFU;
    std::swap(state.s[state.i], state.s[state.j]);
    out[k] = state.s[(state.s[state.i] + state.s[state.j]) & 0xFFU];
  }
  return out;
}
bytes rc4_crypt(rc4_state state, std::span<const byte> input) {
  const bytes ks = rc4_keystream(state, input.size());
  bytes out(input.size());
  for (std::size_t i = 0; i < input.size(); ++i)
    out[i] = input[i] ^ ks[i];
  return out;
}

} // namespace regadgets
