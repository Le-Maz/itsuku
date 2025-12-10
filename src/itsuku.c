#include "itsuku.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// =================================================================
// HELPERS
// =================================================================

/**
 * @brief Converts 4 bytes in little-endian order to a uint32_t.
 *
 * Equivalent to Rust's u32::from_le_bytes(seed_bytes).
 *
 * @param bytes Array of 4 bytes in little-endian order.
 * @return Converted 32-bit unsigned integer.
 */
static uint32_t le_bytes_to_u32(const uint8_t bytes[4]) {
  // Little-endian: bytes[0] is the least significant byte
  uint32_t result = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
                    ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
  return result;
}

// =================================================================
// calculate_argon2_index
// RFC 9106, Section 3.4.2
// =================================================================

size_t calculate_argon2_index(uint8_t seed_bytes[4], size_t original_index) {
  // Convert seed bytes to a 64-bit integer (Rust: u64 from u32)
  uint64_t seed_integer_value = le_bytes_to_u32(seed_bytes);

  // Squaring and shift as in Rust wrapping arithmetic
  uint64_t x = (seed_integer_value * seed_integer_value) >> 32;

  // Multiply by original index and shift
  uint64_t i_u64 = (uint64_t)original_index;
  uint64_t y = (i_u64 * x) >> 32;

  // Subtract to compute Argon2-style index
  uint64_t z = (i_u64 - 1) - y;

  return (size_t)z;
}

// =================================================================
// calculate_phi_variant_index
// =================================================================

size_t calculate_phi_variant_index(size_t original_index, size_t argon2_index,
                                   size_t variant_identifier) {
  if (original_index == 0) {
    return 0;
  }

  size_t index;

  // Select the phi variant using variant_identifier % 12
  switch (variant_identifier % 12) {

  case 0:
    // phi_0(i) = i - 1
    index = original_index - 1;
    break;

  case 1:
    // phi_1(i) = phi(i)
    index = argon2_index;
    break;

  case 2:
    // phi_2(i) = (phi(i) + i) / 2
    index = (argon2_index + original_index) / 2;
    break;

  case 3:
    // phi_3(i) = 7 * i / 8
    index = (original_index * 7) / 8;
    break;

  case 4:
    // phi_4(i) = (phi(i) + 3 * i) / 4
    index = (argon2_index + original_index * 3) / 4;
    break;

  case 5:
    // phi_5(i) = (phi(i) + 5 * i) / 8
    index = (argon2_index + original_index * 5) / 8;
    break;

  case 6:
    // phi_6(i) = 3 * i / 4
    index = (original_index * 3) / 4;
    break;

  case 7:
    // phi_7(i) = i / 2
    index = original_index / 2;
    break;

  case 8:
    // phi_8(i) = i / 4
    index = original_index / 4;
    break;

  case 9:
    // phi_9(i) = 0
    index = 0;
    break;

  case 10:
    // phi_10(i) = (7 * phi(i)) / 8
    index = (argon2_index * 7) / 8;
    break;

  case 11:
    // phi_11(i) = (7 * i) / 8
    index = (original_index * 7) / 8;
    break;

  default:
    abort(); // Unreachable
  }

  // Ensure the result satisfies 0 <= index < original_index
  index %= original_index;

  return index;
}
