# regadgets_cpp

`regadgets_cpp` 是一个 C++ 工具库，提供以下能力：

- 编码与解码
- 哈希 / 摘要 / HMAC
- 流密码与分组密码
- 位运算与数据转换
- 数学与矩阵运算
- 伪随机数生成器
- 逆向辅助工具

公开入口头文件：

```cpp
#include "regadgets/regadgets.hpp"
```

如果你只想使用某个模块，也可以按分类包含对应头文件，例如：

```cpp
#include "regadgets/encoding/base64.hpp"
#include "regadgets/hash/sha256.hpp"
#include "regadgets/crypto/block/aes.hpp"
```

## 1. 构建与安装

### 1.1 构建

```powershell
cmake -S . -B build -DREGADGETS_BUILD_EXAMPLES=ON -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

### 1.2 安装

```powershell
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=D:/local/regadgets_cpp
cmake --build build --target install
```

### 1.3 在其他 CMake 项目中使用

```cmake
find_package(regadgets_cpp CONFIG REQUIRED)
add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE regadgets::regadgets_cpp)
```

## 2. 基本类型

命名空间：`regadgets`

常用类型：

```cpp
using byte = std::uint8_t;
using bytes = std::vector<byte>;
using matrix = std::vector<std::vector<double>>;
```

常用配置结构：

```cpp
struct aes_options {
    block_mode mode = block_mode::ecb;
    bytes iv{};
    bool pkcs7_padding = true;
};

struct aes_params {
    std::span<const byte, 256> sbox;
    std::span<const byte, 256> inv_sbox;
    std::span<const byte, 15> rcon;
    std::size_t rounds = 0;
};

struct xxtea_options {
    std::uint32_t rounds_bias = 0;
    std::uint32_t shift = 2;
};

struct hmac_result {
    bytes raw;
    std::string hex;
};
```


## 3. API 调用说明

### 3.1 位运算与数据转换

头文件：

- `regadgets/bitwise/data_conversion.hpp`
- `regadgets/bitwise/bit_operations.hpp`

#### 3.1.1 字符串 / 十六进制 / 字节转换

```cpp
bytes from_string(std::string_view input);
std::string to_string(std::span<const byte> input);
std::string to_hex(std::span<const byte> input, bool uppercase = false);
bytes from_hex(std::string_view hex);
```

示例：

```cpp
auto raw = from_string("hello");
auto hex = to_hex(raw);
auto raw2 = from_hex(hex);
auto text = to_string(raw2);
```

#### 3.1.2 整数与字节序转换

```cpp
std::uint16_t bytes_to_word(std::span<const byte> input, bool little_endian = true);
std::uint32_t bytes_to_dword(std::span<const byte> input, bool little_endian = true);
std::uint64_t bytes_to_qword(std::span<const byte> input, bool little_endian = true);

bytes word_to_bytes(std::uint16_t value, bool little_endian = true);
bytes dword_to_bytes(std::uint32_t value, bool little_endian = true);
bytes qword_to_bytes(std::uint64_t value, bool little_endian = true);

bytes pack_dword(std::span<const std::uint32_t> values, bool little_endian = true);
std::vector<std::uint32_t> unpack_dword(std::span<const byte> input, bool little_endian = true);
std::uint32_t bswap32(std::uint32_t value) noexcept;
```

示例：

```cpp
auto bytes4 = dword_to_bytes(0x12345678u);
auto value = bytes_to_dword(bytes4);
auto packed = pack_dword(std::array<std::uint32_t, 2>{1u, 2u});
auto unpacked = unpack_dword(packed);
```

#### 3.1.3 循环位移与按位异或

```cpp
template <typename T>
constexpr T rol(T value, unsigned int shift) noexcept;

template <typename T>
constexpr T ror(T value, unsigned int shift) noexcept;

bytes bxor(std::span<const byte> lhs, std::span<const byte> rhs);
bytes bxor_cycle(std::span<const byte> lhs, std::span<const byte> rhs);
bytes bxorr_enc(std::span<const byte> input, byte seed = 0);
bytes bxorr_dec(std::span<const byte> input, byte seed = 0);
bytes bxorl_enc(std::span<const byte> input, byte seed = 0);
bytes bxorl_dec(std::span<const byte> input, byte seed = 0);
```

示例：

```cpp
auto x = rol<std::uint32_t>(0x12345678u, 5);
auto y = ror<std::uint32_t>(0x12345678u, 5);
auto z = bxor(from_hex("aabbccdd"), from_hex("01020304"));
auto roundtrip = bxorr_dec(bxorr_enc(from_string("hello"), 0x5a), 0x5a);
```

### 3.2 编码算法

头文件目录：`regadgets/encoding/`

#### 3.2.1 Base16 / Base32 / Base45 / Base58 / Base62 / Base64 / Base85 / Base91 / Base92

统一接口风格：

```cpp
std::string encode_bXX(std::span<const byte> input, std::string_view alphabet = ...);
bytes decode_bXX(std::string_view input, std::string_view alphabet = ...);
```

可用函数：

- `encode_b16` / `decode_b16`
- `encode_b32` / `decode_b32`
- `encode_b45` / `decode_b45`
- `encode_b58` / `decode_b58`
- `encode_b62` / `decode_b62`
- `encode_b64` / `decode_b64`
- `encode_b85` / `decode_b85`
- `encode_b91` / `decode_b91`
- `encode_b92` / `decode_b92`

示例：

```cpp
auto plain = from_string("hello");

auto b16 = encode_b16(plain);
auto b32 = encode_b32(plain);
auto b64 = encode_b64(plain);
auto b85 = encode_b85(plain);

auto raw16 = decode_b16(b16);
auto raw32 = decode_b32(b32);
auto raw64 = decode_b64(b64);
auto raw85 = decode_b85(b85);
```

#### 3.2.2 Base2048

头文件：`regadgets/encoding/base2048.hpp`

只有在开启 `REGADGETS_ENABLE_BASE2048` 时可用：

```cpp
std::u32string encode_b2048(std::span<const byte> input, std::span<const char32_t> alphabet);
bytes decode_b2048(std::u32string_view input, std::span<const char32_t> alphabet);
```

示例：

```cpp
std::array<char32_t, 2048> alphabet{};
for (std::size_t i = 0; i < alphabet.size(); ++i) {
    alphabet[i] = static_cast<char32_t>(0x4e00 + i);
}

auto encoded = encode_b2048(from_string("hello"), alphabet);
auto decoded = decode_b2048(encoded, alphabet);
```

### 3.3 流密码

头文件目录：`regadgets/crypto/stream/`

#### 3.3.1 RC4

```cpp
rc4_state rc4_init(std::span<const byte> key);
bytes rc4_keystream(rc4_state state, std::size_t length);
bytes rc4_crypt(rc4_state state, std::span<const byte> input);
```

示例：

```cpp
auto state = rc4_init(from_string("rc4-key"));
auto keystream = rc4_keystream(state, 16);

auto cipher = rc4_crypt(rc4_init(from_string("rc4-key")), from_string("hello"));
auto plain = rc4_crypt(rc4_init(from_string("rc4-key")), cipher);
```

#### 3.3.2 Salsa20

```cpp
bytes salsa20_crypt(std::span<const byte> key,
                    std::span<const byte> nonce,
                    std::uint64_t counter,
                    std::span<const byte> input,
                    std::size_t rounds = 20);
```

要求：

- `key` 必须是 32 字节
- `nonce` 必须是 8 字节
- `rounds` 必须是偶数

示例：

```cpp
auto key = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
auto nonce = from_hex("0001020304050607");
auto cipher = salsa20_crypt(key, nonce, 1, from_string("hello"));
auto plain = salsa20_crypt(key, nonce, 1, cipher);
```

#### 3.3.3 ChaCha20

```cpp
bytes chacha20_crypt(std::span<const byte> key,
                     std::span<const byte> nonce,
                     std::uint32_t counter,
                     std::span<const byte> input,
                     std::size_t rounds = 20);
```

要求：

- `key` 必须是 32 字节
- `nonce` 必须是 12 字节
- `rounds` 必须是偶数

示例：

```cpp
auto key = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
auto nonce = from_hex("000102030405060708090a0b");
auto cipher = chacha20_crypt(key, nonce, 1, from_string("hello"));
auto plain = chacha20_crypt(key, nonce, 1, cipher);
```

### 3.4 分组密码与对称加密

头文件目录：`regadgets/crypto/block/`

#### 3.4.1 TEA

单块接口：

```cpp
std::array<std::uint32_t, 2> tea_encrypt(std::array<std::uint32_t, 2> block,
                                         std::array<std::uint32_t, 4> key,
                                         std::uint32_t rounds = 32);
std::array<std::uint32_t, 2> tea_decrypt(std::array<std::uint32_t, 2> block,
                                         std::array<std::uint32_t, 4> key,
                                         std::uint32_t rounds = 32);
```

字节流接口：

```cpp
bytes tea_encrypt(std::span<const byte> input,
                  std::array<std::uint32_t, 4> key,
                  std::uint32_t rounds = 32);
bytes tea_decrypt(std::span<const byte> input,
                  std::array<std::uint32_t, 4> key,
                  std::uint32_t rounds = 32);
```

说明：

- 字节流接口默认按 8 字节分组
- 加密时自动做 `PKCS#7` padding
- 解密时自动去除 padding

示例：

```cpp
std::array<std::uint32_t, 4> key{
    0x01234567u, 0x89abcdefu, 0xfedcba98u, 0x76543210u
};

auto cipher = tea_encrypt(from_string("tea demo"), key);
auto plain = tea_decrypt(cipher, key);
```

#### 3.4.2 XTEA

单块接口：

```cpp
std::array<std::uint32_t, 2> xtea_encrypt(std::array<std::uint32_t, 2> block,
                                          std::array<std::uint32_t, 4> key,
                                          std::uint32_t rounds = 32);
std::array<std::uint32_t, 2> xtea_decrypt(std::array<std::uint32_t, 2> block,
                                          std::array<std::uint32_t, 4> key,
                                          std::uint32_t rounds = 32);
```

字节流接口：

```cpp
bytes xtea_encrypt(std::span<const byte> input,
                   std::array<std::uint32_t, 4> key,
                   std::uint32_t rounds = 32);
bytes xtea_decrypt(std::span<const byte> input,
                   std::array<std::uint32_t, 4> key,
                   std::uint32_t rounds = 32);
```

说明与 TEA 相同：默认 8 字节分组，自动 PKCS#7 padding。

示例：

```cpp
std::array<std::uint32_t, 4> key{
    0x01234567u, 0x89abcdefu, 0xfedcba98u, 0x76543210u
};

auto cipher = xtea_encrypt(from_string("xtea demo"), key);
auto plain = xtea_decrypt(cipher, key);
```

#### 3.4.3 XXTEA

```cpp
bytes xxtea_encrypt(std::span<const byte> input,
                    std::array<std::uint32_t, 4> key,
                    xxtea_options options = {});
bytes xxtea_decrypt(std::span<const byte> input,
                    std::array<std::uint32_t, 4> key,
                    xxtea_options options = {});
```

示例：

```cpp
xxtea_options options;
std::array<std::uint32_t, 4> key{
    0x01234567u, 0x89abcdefu, 0xfedcba98u, 0x76543210u
};

auto cipher = xxtea_encrypt(from_string("hello"), key, options);
auto plain = xxtea_decrypt(cipher, key, options);
```

#### 3.4.4 RC5

```cpp
bytes rc5_encrypt(std::span<const byte> input,
                  std::span<const byte> key,
                  std::uint32_t word_bits = 32,
                  std::uint32_t rounds = 12);
bytes rc5_decrypt(std::span<const byte> input,
                  std::span<const byte> key,
                  std::uint32_t word_bits = 32,
                  std::uint32_t rounds = 12);
```

说明：

- 当前实现只支持 `RC5-32`
- 默认 8 字节块
- 加密自动 `PKCS#7` padding

示例：

```cpp
auto cipher = rc5_encrypt(from_string("hello"), from_string("rc5-key"));
auto plain = rc5_decrypt(cipher, from_string("rc5-key"));
```

#### 3.4.5 AES

```cpp
struct aes_params {
    std::span<const byte, 256> sbox;
    std::span<const byte, 256> inv_sbox;
    std::span<const byte, 15> rcon;
    std::size_t rounds = 0;
};

inline constexpr std::array<byte, 256> aes_default_sbox = ...;
inline constexpr std::array<byte, 256> aes_default_inv_sbox = ...;
inline constexpr std::array<byte, 15> aes_default_rcon = ...;
inline constexpr aes_params aes128_default_params = ...;
inline constexpr aes_params aes256_default_params = ...;

bytes aes128_encrypt(std::span<const byte> input, std::span<const byte> key,
                     const aes_params& params, aes_options options = {});
bytes aes128_decrypt(std::span<const byte> input, std::span<const byte> key,
                     const aes_params& params, aes_options options = {});
bytes aes128_encrypt(std::span<const byte> input, std::span<const byte> key,
                     aes_options options = {});
bytes aes128_decrypt(std::span<const byte> input, std::span<const byte> key,
                     aes_options options = {});

bytes aes256_encrypt(std::span<const byte> input, std::span<const byte> key,
                     const aes_params& params, aes_options options = {});
bytes aes256_decrypt(std::span<const byte> input, std::span<const byte> key,
                     const aes_params& params, aes_options options = {});
bytes aes256_encrypt(std::span<const byte> input, std::span<const byte> key,
                     aes_options options = {});
bytes aes256_decrypt(std::span<const byte> input, std::span<const byte> key,
                     aes_options options = {});

std::string aes_encrypt(std::string_view input, std::string_view key,
                        aes_options options = {},
                        bool input_is_hex = false,
                        bool output_hex = true);
std::string aes_decrypt(std::string_view input, std::string_view key,
                        aes_options options = {},
                        bool input_is_hex = true,
                        bool output_hex = false);
```

说明：

- `aes128_*` 要求 key 为 16 字节
- `aes256_*` 要求 key 为 32 字节
- 支持 `ecb/cbc/pcbc/cfb/ofb/ctr`
- `cbc/cfb/ofb/ctr` 通常需要 `iv`
- 默认自动 `PKCS#7` padding
- 传入 `aes_params` 时，可以自定义 `S-box`、逆 `S-box`、`rcon` 和轮数
- 当前版本还不能从外部直接注入 `ShiftRows / MixColumns / KeySchedule` 的自定义规则
- `rounds = 0` 表示使用该 key 长度对应的默认轮数：AES-128 为 10，AES-256 为 14

标准用法示例：

```cpp
aes_options options;
options.mode = block_mode::cbc;
options.iv = from_hex("00112233445566778899aabbccddeeff");

auto key128 = from_string("0123456789abcdef");
auto cipher = aes128_encrypt(from_string("hello"), key128, options);
auto plain = aes128_decrypt(cipher, key128, options);

auto cipher_hex = aes_encrypt("hello", "0123456789abcdef", options);
auto plain_text = aes_decrypt(cipher_hex, "0123456789abcdef", options);
```

RE / 魔改场景示例：

```cpp
std::array<byte, 256> my_sbox = aes_default_sbox;
std::array<byte, 256> my_inv_sbox = aes_default_inv_sbox;
std::array<byte, 15> my_rcon = aes_default_rcon;

my_sbox[0x00] = 0x7c;
my_sbox[0x01] = 0x63;
my_inv_sbox[0x63] = 0x01;
my_inv_sbox[0x7c] = 0x00;

aes_params params{
    std::span<const byte, 256>(my_sbox),
    std::span<const byte, 256>(my_inv_sbox),
    std::span<const byte, 15>(my_rcon),
    10
};

auto key = from_string("0123456789abcdef");
auto data = from_string("hello");
auto cipher = aes128_encrypt(data, key, params, options);
auto plain = aes128_decrypt(cipher, key, params, options);
```
目前仅aes支持传参的方式定制魔改，后续会考虑所有的算法都优化成可自定义组件这种类型的代码


#### 3.4.6 DES

```cpp
bytes des_encrypt(std::span<const byte> input,
                  std::span<const byte> key,
                  block_mode mode = block_mode::ecb,
                  std::span<const byte> iv = {});
bytes des_decrypt(std::span<const byte> input,
                  std::span<const byte> key,
                  block_mode mode = block_mode::ecb,
                  std::span<const byte> iv = {});
```

说明：

- key 必须为 8 字节
- 默认 8 字节块
- 默认自动 `PKCS#7` padding

示例：

```cpp
auto key = from_hex("133457799BBCDFF1");
auto iv = from_hex("0102030405060708");
auto cipher = des_encrypt(from_string("DES stream demo"), key, block_mode::cbc, iv);
auto plain = des_decrypt(cipher, key, block_mode::cbc, iv);
```

#### 3.4.7 3DES

```cpp
bytes tripledes_encrypt(std::span<const byte> input,
                        std::span<const byte> key,
                        block_mode mode = block_mode::ecb,
                        std::span<const byte> iv = {});
bytes tripledes_decrypt(std::span<const byte> input,
                        std::span<const byte> key,
                        block_mode mode = block_mode::ecb,
                        std::span<const byte> iv = {});
```

说明：

- key 必须为 16 字节或 24 字节
- 默认自动 `PKCS#7` padding

示例：

```cpp
auto key = from_string("0123456789abcdefghijklmn");
auto iv = from_hex("0102030405060708");
auto cipher = tripledes_encrypt(from_string("DES stream demo"), key, block_mode::cbc, iv);
auto plain = tripledes_decrypt(cipher, key, block_mode::cbc, iv);
```

#### 3.4.8 Blowfish

```cpp
bytes blowfish_encrypt(std::span<const byte> input,
                       std::span<const byte> key,
                       block_mode mode = block_mode::ecb,
                       std::span<const byte> iv = {});
bytes blowfish_decrypt(std::span<const byte> input,
                       std::span<const byte> key,
                       block_mode mode = block_mode::ecb,
                       std::span<const byte> iv = {});
```

说明：

- key 长度为 1 到 56 字节
- 默认 8 字节块
- 默认自动 `PKCS#7` padding

示例：

```cpp
auto key = from_string("blowfish-key");
auto iv = from_hex("0102030405060708");
auto cipher = blowfish_encrypt(from_string("DES stream demo"), key, block_mode::cbc, iv);
auto plain = blowfish_decrypt(cipher, key, block_mode::cbc, iv);
```

#### 3.4.9 SM4

块接口：

```cpp
std::array<byte, 16> SM4_encrypt(std::span<const byte, 16> block,
                                 std::span<const byte, 16> key);
std::array<byte, 16> SM4_decrypt(std::span<const byte, 16> block,
                                 std::span<const byte, 16> key);
```

模式接口：

```cpp
bytes sm4_ecb_encrypt(std::span<const byte> input, std::span<const byte, 16> key);
bytes sm4_ecb_decrypt(std::span<const byte> input, std::span<const byte, 16> key);
bytes sm4_cbc_encrypt(std::span<const byte> input,
                      std::span<const byte, 16> key,
                      std::span<const byte, 16> iv);
bytes sm4_cbc_decrypt(std::span<const byte> input,
                      std::span<const byte, 16> key,
                      std::span<const byte, 16> iv);
```

说明：

- key 固定为 16 字节
- ECB / CBC 接口自动 `PKCS#7` padding

示例：

```cpp
auto key = from_hex("0123456789abcdeffedcba9876543210");
auto block = from_hex("0123456789abcdeffedcba9876543210");
auto encrypted = SM4_encrypt(std::span<const byte, 16>(block.data(), 16),
                             std::span<const byte, 16>(key.data(), 16));

auto iv = from_hex("000102030405060708090a0b0c0d0e0f");
auto cipher = sm4_cbc_encrypt(from_string("hello"), 
                              std::span<const byte, 16>(key.data(), 16),
                              std::span<const byte, 16>(iv.data(), 16));
auto plain = sm4_cbc_decrypt(cipher,
                             std::span<const byte, 16>(key.data(), 16),
                             std::span<const byte, 16>(iv.data(), 16));
```

### 3.5 哈希 / 摘要 / HMAC

头文件目录：`regadgets/hash/`

#### 3.5.1 MD5 / SHA1 / SHA256 / SHA512

```cpp
bytes md5(std::span<const byte> input);
bytes sha1(std::span<const byte> input);
bytes sha256(std::span<const byte> input);
bytes sha512(std::span<const byte> input);
```

示例：

```cpp
auto plain = from_string("hello");

auto md5_hex = to_hex(md5(plain));
auto sha1_hex = to_hex(sha1(plain));
auto sha256_hex = to_hex(sha256(plain));
auto sha512_hex = to_hex(sha512(plain));
```

#### 3.5.2 CRC / Adler

```cpp
std::uint32_t crc32(std::span<const byte> input, std::uint32_t seed = 0xFFFFFFFFu);
std::uint64_t crc64(std::span<const byte> input, std::uint64_t seed = 0xFFFFFFFFFFFFFFFFull);
std::uint32_t adler32(std::span<const byte> input);
```

示例：

```cpp
auto plain = from_string("hello");
auto c32 = crc32(plain);
auto c64 = crc64(plain);
auto adler = adler32(plain);
```

#### 3.5.3 HMAC

```cpp
hmac_result hmac_md5(std::span<const byte> key, std::span<const byte> message);
hmac_result hmac_sha1(std::span<const byte> key, std::span<const byte> message);
hmac_result hmac_sha256(std::span<const byte> key, std::span<const byte> message);
```

示例：

```cpp
auto result = hmac_sha256(from_string("secret"), from_string("hello"));
std::cout << result.hex << '\n';
```

### 3.6 数学与矩阵算法

头文件目录：`regadgets/math/`

#### 3.6.1 DCT / IDCT

```cpp
std::vector<double> dct_transform(std::span<const double> input);
std::vector<double> idct_transform(std::span<const double> input);
```

示例：

```cpp
auto dct = dct_transform(std::vector<double>{1.0, 2.0, 3.0, 4.0});
auto idct = idct_transform(dct);
```

#### 3.6.2 矩阵

```cpp
matrix matrix_multiply(const matrix& lhs, const matrix& rhs);
double matrix_determinant(matrix input);
matrix matrix_inverse(matrix input);
matrix generate_matrix_square(std::size_t size,
                              double diagonal = 1.0,
                              double off_diagonal = 0.0);
std::vector<double> flat_matrix(const matrix& input);
```

示例：

```cpp
matrix a{{1.0, 2.0}, {3.0, 4.0}};
matrix b{{5.0, 6.0}, {7.0, 8.0}};

auto c = matrix_multiply(a, b);
auto det = matrix_determinant(a);
auto inv = matrix_inverse(a);
auto square = generate_matrix_square(3, 2.0, 0.5);
auto flat = flat_matrix(square);
```

### 3.7 伪随机数生成器

头文件目录：`regadgets/prng/`

#### 3.7.1 GLIBCRand

```cpp
class GLIBCRand {
public:
    explicit GLIBCRand(std::uint32_t seed = 1);
    void seed(std::uint32_t value);
    std::uint32_t next();
    std::vector<std::uint32_t> sequence(std::size_t count);
};
```

示例：

```cpp
GLIBCRand rng(12345);
auto value = rng.next();
auto seq = rng.sequence(5);
```

#### 3.7.2 WindowsRand

```cpp
class WindowsRand {
public:
    explicit WindowsRand(std::uint32_t seed = 1);
    void seed(std::uint32_t value);
    std::uint32_t next();
    std::vector<std::uint32_t> sequence(std::size_t count);
};
```

示例：

```cpp
WindowsRand rng(12345);
auto value = rng.next();
auto seq = rng.sequence(5);
```

#### 3.7.3 MT19937

头文件：`regadgets/prng/mt19937.hpp`

```cpp
class MT19937 {
public:
    static constexpr std::size_t state_size = 624;

    explicit MT19937(std::uint32_t seed = 5489u);
    void seed(std::uint32_t value);
    std::uint32_t next();
    std::vector<std::uint32_t> sequence(std::size_t count);
};
```

说明：

- 这是标准 `MT19937` 梅森旋转伪随机数生成器。
- `state_size` 固定为 `624`，也是恢复内部状态所需的最少样本数。
- `sequence(n)` 会连续生成 `n` 个 `std::uint32_t` 输出。

示例：

```cpp
MT19937 rng(5489u);
auto first = rng.next();
auto seq = rng.sequence(5);
```

#### 3.7.4 MT19937Predictor

```cpp
class MT19937Predictor {
public:
    static constexpr std::size_t state_size = MT19937::state_size;

    void reset();
    void submit(std::uint32_t sample);
    void submit(std::span<const std::uint32_t> samples);
    bool ready() const noexcept;
    std::size_t samples_collected() const noexcept;
    std::uint32_t next();
    std::vector<std::uint32_t> sequence(std::size_t count);
};
```

说明：

- 连续收集 `624` 个 `MT19937` 输出样本后，可以恢复其内部状态。
- `submit(...)` 接收的是生成器已经 temper 之后的公开输出，不需要手动做逆变换。
- `ready()` 为 `true` 后，`next()` / `sequence()` 生成的后续值会与原始生成器保持一致。
- 若样本不足 `624` 个就调用 `next()`，会抛出异常。

示例：

```cpp
MT19937 original(5489u);
MT19937Predictor predictor;

predictor.submit(original.sequence(MT19937::state_size));

if (predictor.ready()) {
    auto expected = original.sequence(3);
    auto predicted = predictor.sequence(3);
}
```

### 3.8 逆向工程辅助工具

头文件：`regadgets/reverse/sbox.hpp`

```cpp
std::pair<bytes, bytes> generate_sbox(std::span<const byte> permutation);
bytes sbox_transform(std::span<const byte> input, std::span<const byte> sbox);
```

说明：

- `generate_sbox({})` 会生成恒等 S-box 与其逆表
- `permutation` 长度必须是 256
- `sbox_transform` 可用于字节替换表映射

示例：

```cpp
auto [sbox, inverse_sbox] = generate_sbox({});
auto transformed = sbox_transform(from_hex("00112233"), sbox);
auto restored = sbox_transform(transformed, inverse_sbox);
```

## 4. 模式与 Padding 约定

### 4.1 `block_mode`

可选模式：

```cpp
enum class block_mode {
    ecb,
    cbc,
    pcbc,
    cfb,
    ofb,
    ctr
};
```

### 4.2 默认 padding 行为

默认自动 `PKCS#7` padding 的接口：

- `aes128_encrypt` / `aes128_decrypt`
- `aes256_encrypt` / `aes256_decrypt`
- `des_encrypt` / `des_decrypt`
- `tripledes_encrypt` / `tripledes_decrypt`
- `blowfish_encrypt` / `blowfish_decrypt`
- `rc5_encrypt` / `rc5_decrypt`
- `tea_encrypt(bytes)` / `tea_decrypt(bytes)`
- `xtea_encrypt(bytes)` / `xtea_decrypt(bytes)`
- `sm4_ecb_encrypt` / `sm4_ecb_decrypt`
- `sm4_cbc_encrypt` / `sm4_cbc_decrypt`

不自动 padding 的接口：

- TEA / XTEA 的单块 `std::array<uint32_t, 2>` 接口
- `SM4_encrypt` / `SM4_decrypt` 单块接口
- `rc4_crypt`
- `salsa20_crypt`
- `chacha20_crypt`
- 哈希与编码类接口

## 5. 示例代码位置

可以直接参考：

- [examples/demo.cpp](D:\Project\regadgets_cpp\examples\demo.cpp)
- [tests/smoke_test.cpp](D:\Project\regadgets_cpp\tests\smoke_test.cpp)



  绝大部分接口使用 `bytes` 作为输入输出，调用前通常用 `from_string` / `from_hex` 做转换。
  若你处理的是文本，解密后通常用 `to_string(...)` 转回字符串。
  块密码如果使用 `cbc/cfb/ofb/ctr`，请显式提供合适长度的 `iv`。
  Base2048 只有在开启 `REGADGETS_ENABLE_BASE2048` 时可用。


