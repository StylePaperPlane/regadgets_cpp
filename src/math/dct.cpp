#include "regadgets/math/dct.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
std::vector<double> dct_transform(std::span<const double> input) {
  std::vector<double> out(input.size(), 0.0);
  for (std::size_t k = 0; k < input.size(); ++k) {
    double sum = 0.0;
    for (std::size_t n = 0; n < input.size(); ++n)
      sum += input[n] * std::cos(kPi * (static_cast<double>(n) + 0.5) *
                                 static_cast<double>(k) /
                                 static_cast<double>(input.size()));
    double factor =
        k == 0 ? std::sqrt(1.0 / input.size()) : std::sqrt(2.0 / input.size());
    out[k] = factor * sum;
  }
  return out;
}
std::vector<double> idct_transform(std::span<const double> input) {
  std::vector<double> out(input.size(), 0.0);
  for (std::size_t n = 0; n < input.size(); ++n) {
    double sum = std::sqrt(1.0 / input.size()) * input[0];
    for (std::size_t k = 1; k < input.size(); ++k)
      sum += std::sqrt(2.0 / input.size()) * input[k] *
             std::cos(kPi * static_cast<double>(k) *
                      (static_cast<double>(n) + 0.5) /
                      static_cast<double>(input.size()));
    out[n] = sum;
  }
  return out;
}

} // namespace regadgets
