#pragma once

#include "regadgets/core/types.hpp"

namespace regadgets {

matrix matrix_multiply(const matrix &lhs, const matrix &rhs);
double matrix_determinant(matrix input);
matrix matrix_inverse(matrix input);
matrix generate_matrix_square(std::size_t size, double diagonal = 1.0,
                              double off_diagonal = 0.0);
std::vector<double> flat_matrix(const matrix &input);

} // namespace regadgets
