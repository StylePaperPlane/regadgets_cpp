#include "regadgets/math/matrix.hpp"
#include "src/crypto/block/common.hpp"

namespace regadgets {
matrix matrix_multiply(const matrix &lhs, const matrix &rhs) {
  if (lhs.empty() || rhs.empty() || lhs[0].size() != rhs.size())
    fail("invalid matrix dimensions");
  matrix out(lhs.size(), std::vector<double>(rhs[0].size(), 0.0));
  for (std::size_t i = 0; i < lhs.size(); ++i)
    for (std::size_t k = 0; k < rhs.size(); ++k)
      for (std::size_t j = 0; j < rhs[0].size(); ++j)
        out[i][j] += lhs[i][k] * rhs[k][j];
  return out;
}
double matrix_determinant(matrix input) {
  std::size_t n = input.size();
  if (n == 0 || input[0].size() != n)
    fail("determinant requires square matrix");
  double det = 1.0;
  for (std::size_t i = 0; i < n; ++i) {
    std::size_t pivot = i;
    for (std::size_t r = i + 1; r < n; ++r)
      if (std::abs(input[r][i]) > std::abs(input[pivot][i]))
        pivot = r;
    if (std::abs(input[pivot][i]) < 1e-12)
      return 0.0;
    if (pivot != i) {
      std::swap(input[pivot], input[i]);
      det = -det;
    }
    det *= input[i][i];
    double inv = 1.0 / input[i][i];
    for (std::size_t r = i + 1; r < n; ++r) {
      double factor = input[r][i] * inv;
      for (std::size_t c = i; c < n; ++c)
        input[r][c] -= factor * input[i][c];
    }
  }
  return det;
}
matrix matrix_inverse(matrix input) {
  std::size_t n = input.size();
  if (n == 0 || input[0].size() != n)
    fail("inverse requires square matrix");
  matrix inv = generate_matrix_square(n);
  for (std::size_t i = 0; i < n; ++i) {
    std::size_t pivot = i;
    for (std::size_t r = i + 1; r < n; ++r)
      if (std::abs(input[r][i]) > std::abs(input[pivot][i]))
        pivot = r;
    if (std::abs(input[pivot][i]) < 1e-12)
      fail("matrix is singular");
    std::swap(input[pivot], input[i]);
    std::swap(inv[pivot], inv[i]);
    double div = input[i][i];
    for (std::size_t c = 0; c < n; ++c) {
      input[i][c] /= div;
      inv[i][c] /= div;
    }
    for (std::size_t r = 0; r < n; ++r) {
      if (r == i)
        continue;
      double factor = input[r][i];
      for (std::size_t c = 0; c < n; ++c) {
        input[r][c] -= factor * input[i][c];
        inv[r][c] -= factor * inv[i][c];
      }
    }
  }
  return inv;
}
matrix generate_matrix_square(std::size_t size, double diagonal,
                              double off_diagonal) {
  matrix out(size, std::vector<double>(size, off_diagonal));
  for (std::size_t i = 0; i < size; ++i)
    out[i][i] = diagonal;
  return out;
}
std::vector<double> flat_matrix(const matrix &input) {
  std::vector<double> out;
  for (const auto &row : input)
    out.insert(out.end(), row.begin(), row.end());
  return out;
}

} // namespace regadgets
