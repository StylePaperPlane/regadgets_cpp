#pragma once

#include "regadgets/core/types.hpp"

#include "regadgets/bitwise/bit_operations.hpp"
#include "regadgets/bitwise/data_conversion.hpp"

#include "regadgets/encoding/base16.hpp"
#include "regadgets/encoding/base2048.hpp"
#include "regadgets/encoding/base32.hpp"
#include "regadgets/encoding/base45.hpp"
#include "regadgets/encoding/base58.hpp"
#include "regadgets/encoding/base62.hpp"
#include "regadgets/encoding/base64.hpp"
#include "regadgets/encoding/base85.hpp"
#include "regadgets/encoding/base91.hpp"
#include "regadgets/encoding/base92.hpp"

#include "regadgets/crypto/stream/chacha20.hpp"
#include "regadgets/crypto/stream/rc4.hpp"
#include "regadgets/crypto/stream/salsa20.hpp"

#include "regadgets/crypto/block/aes.hpp"
#include "regadgets/crypto/block/blowfish.hpp"
#include "regadgets/crypto/block/des.hpp"
#include "regadgets/crypto/block/rc5.hpp"
#include "regadgets/crypto/block/sm4.hpp"
#include "regadgets/crypto/block/tea.hpp"
#include "regadgets/crypto/block/tripledes.hpp"
#include "regadgets/crypto/block/xtea.hpp"
#include "regadgets/crypto/block/xxtea.hpp"

#include "regadgets/hash/checksum.hpp"
#include "regadgets/hash/hmac.hpp"
#include "regadgets/hash/md5.hpp"
#include "regadgets/hash/sha1.hpp"
#include "regadgets/hash/sha256.hpp"
#include "regadgets/hash/sha512.hpp"

#include "regadgets/math/dct.hpp"
#include "regadgets/math/matrix.hpp"

#include "regadgets/prng/glibc_rand.hpp"
#include "regadgets/prng/mt19937.hpp"
#include "regadgets/prng/windows_rand.hpp"

#include "regadgets/reverse/sbox.hpp"
